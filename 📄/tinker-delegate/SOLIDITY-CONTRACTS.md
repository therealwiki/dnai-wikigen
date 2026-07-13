# Solidity Contracts Spec

**Status**: DiligenceRoom.sol implemented and tested; DiligenceRoomAuth.sol not started

## What EXISTS

### DiligenceRoom.sol (282 lines)

Fully implemented escrow contract with:

- **State machine**: Created → Funded → Evaluated → Accepted/Rejected/Expired
- **Deal struct**: seller, buyer, reservePrice, budgetCap, expiry, state, artifactHash, teeIdentity, scoreBand, computeCost, fee, resultHash
- **createDeal**: Seller lists artifact with reserve price, expiry, artifact hash, TEE identity
- **fundDeal**: Buyer deposits ETH as budget cap
- **submitResult**: TEE submits bounded score band + compute cost (only `teeIdentity` can call)
- **acceptDeal**: Buyer accepts, sets payment. Three-way settlement: seller + developer + buyer refund
- **rejectDeal**: Buyer rejects. Two-way: developer gets compute+fee, buyer gets remainder
- **expireDeal**: Anyone calls after deadline. Refund minus any compute costs
- **FEE_BPS**: 100 (1% on compute cost)
- **Events**: DealCreated, DealFunded, EvaluationSubmitted, DealAccepted, DealRejected, DealExpired

### DiligenceRoom.t.sol (347 lines)

Comprehensive test suite:
- Creation, funding, evaluation, accept, reject, expire tests
- Access control: NotBuyer, NotTEE, wrong state reverts
- Edge cases: expired deals, zero-value funding, above-budget payments
- Full lifecycle tests (accept and reject flows)
- **Fuzz test**: `testFuzz_Settlement` — verifies fund conservation with random payment/compute values

### DiligenceRoom.s.sol

Deployment script (exists but not reviewed).

## What's MISSING

### 1. TEE Identity Verification (High Priority)

Currently `teeIdentity` is just an `address` parameter in `createDeal`. Anyone who knows this address can impersonate the TEE. In production, this should be a KMS-derived address verified via the DStack signature chain.

**Approach**: Integrate with `DstackKms` contract patterns from `🔬/dstack/kms/auth-eth/contracts/`:

```solidity
// Option A: Verify on submitResult using DStack signature chain
function submitResult(
    uint256 dealId,
    ScoreBand scoreBand,
    uint256 computeCost,
    bytes32 resultHash,
    bytes calldata attestation  // DStack signature chain proof
) external {
    // Verify: KMS root → app key → derived key → msg.sender
    // This proves msg.sender is running in a verified TEE
    require(_verifyDstackProof(attestation, msg.sender), "Invalid TEE attestation");
    // ... rest of submitResult
}
```

**Option B**: Keep it simple — `teeIdentity` is registered by the developer at deal creation, and the developer is trusted to set the correct KMS-derived address. The TEE's identity is verified off-chain via TDX attestation before the deal is created.

**Recommendation**: Option B for v1 (the developer already trusts the TEE via attestation), Option A for v2.

### 2. DiligenceRoomAuth.sol (Medium Priority)

An `IAppAuth` implementation that governs which TEE apps can interact with the DiligenceRoom:

```solidity
contract DiligenceRoomAuth is IAppAuth {
    mapping(bytes32 => bool) public allowedComposeHashes;
    address public immutable kmsRoot;
    bytes32 public immutable appId;

    function isAppAllowed(AppBootInfo calldata app) external view returns (bool) {
        return app.appId == appId && allowedComposeHashes[app.composeHash];
    }
}
```

This is the same pattern as `DstackApp.sol` but scoped to the DiligenceRoom. It allows KMS to issue keys only to verified TEE instances running approved code.

### 3. Missing Contract Features

| Feature | Description | Priority |
|---|---|---|
| **Artifact encryption key exchange** | On-chain public key commitment for artifact encryption | Medium |
| **Dispute resolution** | Timeout-based dispute if buyer doesn't decide within N blocks | Medium |
| **Multi-evaluator support** | Allow multiple TEE evaluators per deal | Low |
| **Deal cancellation** | Seller can cancel before funding | Low |
| **Batch operations** | Create/fund multiple deals in one transaction | Low |
| **ERC-20 support** | Accept stablecoins (USDC) instead of ETH only | Medium |
| **Reentrancy guard** | Add `nonReentrant` modifier to settlement functions | High |

### 4. Reentrancy Risk

The `acceptDeal`, `rejectDeal`, and `expireDeal` functions use `.call{value:}` for ETH transfers. While state is updated before transfers (checks-effects-interactions), adding OpenZeppelin's `ReentrancyGuard` is a defense-in-depth improvement.

```solidity
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract DiligenceRoom is ReentrancyGuard {
    function acceptDeal(...) external nonReentrant { ... }
    function rejectDeal(...) external nonReentrant { ... }
    function expireDeal(...) external nonReentrant { ... }
}
```

### 5. ScoreBand Alignment

The Solidity `ScoreBand` enum matches the Python `ScoreBand`:

| Solidity | Python | Range |
|---|---|---|
| Negligible (0) | NEGLIGIBLE | <1% |
| Low (1) | LOW | 1-5% |
| Medium (2) | MEDIUM | 5-10% |
| High (3) | HIGH | 10-20% |
| Exceptional (4) | EXCEPTIONAL | >20% |

This alignment is correct and must be maintained if either side changes.

## Implementation Plan

### v1: Ship with current DiligenceRoom.sol
- Add `ReentrancyGuard`
- Deploy to Base Sepolia
- TEE identity set by developer (trusted)
- No on-chain TEE verification

### v2: Add TEE verification
- Deploy `DiligenceRoomAuth` implementing `IAppAuth`
- Integrate DStack signature chain verification in `submitResult`
- Register with `DstackKms` for key issuance

### v3: Feature expansion
- ERC-20 support (USDC)
- Dispute resolution with timeout
- Deal cancellation

## Files

| File | Status | Notes |
|---|---|---|
| `contracts/src/DiligenceRoom.sol` | Done | 282 lines, full state machine |
| `contracts/test/DiligenceRoom.t.sol` | Done | 347 lines, fuzz tests |
| `contracts/script/DiligenceRoom.s.sol` | Done | Deployment script |
| `contracts/src/DiligenceRoomAuth.sol` | Not started | IAppAuth for TEE verification |
