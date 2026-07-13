# TEE-Authenticated API for Email Oracle

**Status**: Not started
**Depends on**: Email oracle API (`api.py`), dstack KMS, on-chain contract infrastructure

## Problem

The email oracle API (`POST /pin`, `GET /inbox`, `GET /health`) is currently **unauthenticated**. Any HTTP client that can reach the oracle can extract OTPs, list emails, and read credentials status. In production, only trusted TEE services (like tinker-delegate) should be able to call the oracle.

## Current State

### What EXISTS

- `email_oracle/api.py` — FastAPI server with 4 endpoints, **zero auth**
- `GET /attestation` — returns TDX quote stub (real in dstack mode)
- `_get_tdx_quote()` stub — calls `TappdClient` when `DSTACK_ENABLED=true`
- `tinker_delegate/oracle_client.py` — plain HTTP client, no auth headers

### What's MISSING

- Mutual TDX attestation between oracle and consumer CVMs
- Consumer allowlist (which apps can call which endpoints)
- Request signing / verification middleware
- On-chain consumer registry (optional, for governance)

## Design: Cross-CVM Authentication

Since oracle and tinker-delegate run in **separate CVMs** (cross-compose decided), they each have their own `app_id` and compose hash. Authentication uses the **DStack signature chain** pattern from `🔬/amiller/dstack-tutorial`.

### Option A: RA-TLS (Recommended for v1)

**How it works:**
1. Both CVMs get TLS certificates from dstack-KMS that embed their TDX quotes
2. Oracle accepts connections only from TLS clients whose certificate contains a valid TDX quote with an allowlisted `compose_hash`
3. Mutual TLS — both sides verify each other

**Implementation:**
```
Oracle CVM:
  - On boot: get RA-TLS cert from KMS via tappd socket
  - Configure FastAPI/uvicorn with RA-TLS server cert
  - Middleware: extract client cert → parse TDX quote → check compose_hash
  - Reject if client's compose_hash not in allowlist

Tinker-Delegate CVM:
  - On boot: get RA-TLS client cert from KMS
  - OracleClient uses httpx with client cert
```

**Allowlist management:**
- Hardcoded in oracle config for v1 (list of allowed compose hashes)
- On-chain registry for v2 (see below)

**Pros:** Standard TLS, no custom crypto, dstack provides the certs
**Cons:** Requires both CVMs to have KMS access, cert rotation coordination

### Option B: DStack Signature Chain (Bearer Token)

**How it works:**
1. Tinker-delegate derives a signing key from KMS: `derive_key(path="/email-oracle/auth", subject="tinker-delegate")`
2. Signs each request: `signature = sign(kms_derived_key, request_body + timestamp + nonce)`
3. Oracle verifies the signature chain: KMS root → app key → derived key → message

**Implementation:**
```python
# Tinker-delegate side (oracle_client.py)
class AuthenticatedOracleClient:
    def __init__(self, settings):
        self.base_url = settings.oracle_url
        # Derive signing key from KMS
        from dstack_sdk import TappdClient
        client = TappdClient()
        key_resp = client.derive_key(path="/email-oracle/auth", subject="tinker-delegate")
        self._signing_key = key_resp.key

    def _sign_request(self, body: bytes) -> dict:
        timestamp = str(int(time.time()))
        nonce = os.urandom(16).hex()
        message = body + timestamp.encode() + nonce.encode()
        signature = hmac.new(self._signing_key, message, hashlib.sha256).hexdigest()
        return {
            "X-TEE-Timestamp": timestamp,
            "X-TEE-Nonce": nonce,
            "X-TEE-Signature": signature,
        }

# Oracle side (middleware)
async def verify_tee_request(request: Request):
    # 1. Extract headers
    # 2. Verify timestamp freshness (< 60s)
    # 3. Verify nonce uniqueness (replay protection)
    # 4. Recompute HMAC with expected key
    # 5. Compare signatures
```

**Problem with Option B:** Both CVMs need to derive the **same** key or the oracle needs to know the delegate's public key. With separate `app_id`s, `derive_key` produces different keys. This means the oracle needs the delegate's KMS-derived public key, which circles back to needing an out-of-band key exchange or on-chain registry.

### Recommendation: Option A (RA-TLS) for v1

RA-TLS is the natural choice for cross-CVM auth in dstack. It's what the platform is designed for. The oracle just needs a TLS server with client cert verification, and the delegate needs a TLS client cert from KMS.

## On-Chain Consumer Registry (v2)

For governance, an on-chain contract can manage which compose hashes are allowed to call the oracle. This follows the `IAppAuth` / `DstackApp` pattern from `🔬/dstack/kms/auth-eth/contracts/`.

```solidity
contract EmailOracleConsumerRegistry {
    address public owner;
    mapping(bytes32 => bool) public allowedConsumers; // compose_hash => allowed

    event ConsumerAdded(bytes32 indexed composeHash);
    event ConsumerRemoved(bytes32 indexed composeHash);

    function addConsumer(bytes32 composeHash) external onlyOwner {
        allowedConsumers[composeHash] = true;
        emit ConsumerAdded(composeHash);
    }

    function removeConsumer(bytes32 composeHash) external onlyOwner {
        allowedConsumers[composeHash] = false;
        emit ConsumerRemoved(composeHash);
    }

    function isAllowed(bytes32 composeHash) external view returns (bool) {
        return allowedConsumers[composeHash];
    }
}
```

The oracle reads this contract on boot and periodically refreshes, or the middleware checks on each request. A `TimelockAppAuth`-style delay could be added for consumer additions.

## Endpoint-Level Access Control

Not all consumers need all endpoints:

| Endpoint | tinker-delegate | Debug/Admin |
|---|---|---|
| `POST /pin` | Yes | No |
| `GET /health` | Yes | Yes |
| `GET /inbox` | No | Yes |
| `GET /attestation` | Yes | Yes |

Implementation: role-based middleware on top of RA-TLS. The client cert's compose hash maps to a role, and each endpoint checks the role.

## Implementation Plan

### Phase 1: Hardcoded Allowlist (ship first)
1. Add RA-TLS server support to email oracle
2. Add RA-TLS client cert to `OracleClient`
3. Middleware: verify client cert → extract compose_hash → check hardcoded allowlist
4. Config: `ALLOWED_CONSUMER_HASHES=hash1,hash2`

### Phase 2: On-Chain Registry
1. Deploy `EmailOracleConsumerRegistry` contract
2. Oracle reads allowlist from contract instead of config
3. Add timelock governance for consumer additions

### Phase 3: Per-Endpoint RBAC
1. Map compose_hash → role
2. Endpoint-level `@requires_role("consumer")` decorator
3. Admin endpoints behind separate role

## Files to Create/Modify

| File | Action | Description |
|---|---|---|
| `email_oracle/auth.py` | Create | RA-TLS middleware, cert verification |
| `email_oracle/api.py` | Modify | Add auth middleware to protected endpoints |
| `email_oracle/config.py` | Modify | Add `ALLOWED_CONSUMER_HASHES` config |
| `tinker_delegate/oracle_client.py` | Modify | Add RA-TLS client cert |
| `tinker_delegate/config.py` | Modify | Add KMS cert paths |
| `contracts/src/EmailOracleConsumerRegistry.sol` | Create (v2) | On-chain allowlist |

## Open Questions

1. **RA-TLS cert format in dstack**: Does dstack-KMS issue standard X.509 certs with TDX quote extensions, or do we need to parse the quote separately?
2. **Cert rotation**: How often do RA-TLS certs expire? Need auto-renewal.
3. **Fallback for local dev**: When `DSTACK_ENABLED=false`, bypass auth entirely (current behavior) or use a shared dev secret?
4. **Oracle-to-delegate auth**: Does the oracle ever need to call the delegate? Currently no — it's strictly consumer → oracle.
