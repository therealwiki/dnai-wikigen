# Stripe Billing Automation Spec

**Status**: Implemented
**Location**: `billing.py` (349 lines), `card_channel.py` (253 lines), `crypto.py` (134 lines)

## What EXISTS

### billing.py — Browser-Based Stripe Interaction

All billing operations use Playwright CDP to interact with the Tinker billing page at `tinker-console.thinkingmachines.ai/billing/balance`. This is necessary because Tinker doesn't expose a billing API — it's all via the web console with Stripe Elements iframes.

**Implemented functions:**

| Function | Description | Status |
|---|---|---|
| `add_payment_method(card, settings)` | Fill Stripe card iframe + address fields, submit | Done |
| `add_balance(amount_dollars, settings)` | Click "Add to balance", enter amount, confirm | Done |
| `configure_auto_reload(enabled, threshold, amount)` | Toggle auto-reload checkbox, set params | Done |
| `get_balance(settings)` | Scrape current balance from billing page | Done |
| `CardDetails` | Data class with `zero()` method | Done |

**Stripe iframe handling:**
- `_find_stripe_card_frame()` — finds `elements-inner-card` or `__privateStripeFrame` iframe
- `_fill_stripe_card()` — types card number, exp date, CVC into Stripe Elements inputs
- Handles both combined and separate Stripe input variants

### card_channel.py — Encrypted Card Delivery

| Component | Description | Status |
|---|---|---|
| `CardPayload` | Pydantic model for plaintext card data | Done |
| `EncryptedCardPayload` | Pydantic model for encrypted card data | Done |
| `BalancePayload` | Pydantic model for balance requests | Done |
| `BillingResponse` | Response with success, error, balance, tdx_quote | Done |
| `get_tee_keypair()` | Singleton X25519 keypair, generated on boot | Done |
| `get_attestation()` | TDX quote + encryption public key | Done |
| `handle_card_update()` | Plaintext path (dev only) | Done |
| `handle_encrypted_card_update()` | Decrypt → fill form → zero memory | Done |
| `handle_add_balance()` | Add credit using card on file | Done |
| `handle_get_balance()` | Read current balance | Done |

### crypto.py — X25519 + AES-256-GCM

| Component | Description | Status |
|---|---|---|
| `TEEKeyPair` | X25519 keypair, `decrypt()` method | Done |
| `encrypt_for_tee()` | ECIES: X25519 ECDH → HKDF-SHA256 → AES-256-GCM | Done |
| `encrypt_card_payload()` | Convenience: dict → hex wire format | Done |
| `EncryptedPayload` | Dataclass with `to_hex()` / `from_hex()` | Done |

### API Endpoints (api.py)

| Endpoint | Method | Description | Status |
|---|---|---|---|
| `/attestation` | GET | TDX quote + encryption public key | Done |
| `/billing/balance` | GET | Current balance | Done |
| `/billing/card` | POST | Plaintext card (dev only) | Done |
| `/billing/card/encrypted` | POST | Encrypted card (production) | Done |
| `/billing/add-balance` | POST | Add credit | Done |

### CLI Commands (main.py)

| Command | Description | Status |
|---|---|---|
| `tinker-delegate balance` | Get balance | Done |
| `tinker-delegate add-card --number ... --cvc ...` | Add card (plaintext, dev) | Done |
| `tinker-delegate add-balance 100` | Add $100 credit | Done |

## Known Issues

### 1. Python String Immutability

`CardDetails.zero()` and the `plaintext_bytes = b"\x00" * len(plaintext_bytes)` pattern don't truly zero memory. Python strings are immutable — the original string objects persist until garbage collected.

**Impact**: Low in a TEE (memory is encrypted by TDX), but violates the principle of least privilege.

**Potential fix**: Use `ctypes.memset` on the string's buffer, or use `mmap` for sensitive data and explicitly zero the mapped region. Not worth the complexity for v1 given TDX memory encryption.

### 2. Stripe UI Fragility

All billing operations depend on CSS selectors and page structure of Tinker's billing console. If Thinking Machines updates their UI, the selectors break silently.

**Mitigation**: Screenshot on every operation (already done: `screenshot_billing_filled.png`, `screenshot_billing_result.png`). Add integration test that runs monthly against real UI.

### 3. No Retry Logic

If the Stripe iframe fails to load or the form submission errors, the operation fails without retry.

**Fix**: Add retry with exponential backoff for transient failures (iframe not found, timeout).

### 4. Auto-Reload Not Tested

`configure_auto_reload()` is implemented but the selectors are speculative — they depend on the exact Tinker billing UI structure for auto-reload settings.

### 5. Balance Parsing

`get_balance()` uses a regex `text.match(/\$[\d,.]+/)` to extract the balance from page text. Fragile.

## Remaining Work

| Task | Priority | Effort |
|---|---|---|
| Integration test with real Tinker account | High | 2 hours |
| Add retry logic to Stripe iframe interaction | Medium | 1 hour |
| Verify auto-reload UI selectors | Medium | 1 hour |
| Add balance alerting (low balance warning) | Medium | 2 hours |
| Document the developer-side encryption flow | Low | 1 hour |
| Explore Tinker API for programmatic billing (if available) | Low | Research |

## Developer Card Encryption Flow

For reference, the full developer-side flow to add a card:

```python
import requests
from tinker_delegate.crypto import encrypt_card_payload

# 1. Get TEE attestation
att = requests.get("https://tee-host/attestation").json()
# TODO: verify TDX quote (code measurements, etc.)

# 2. Encrypt card details
card = {
    "card_number": "4242424242424242",
    "exp_month": "12", "exp_year": "28",
    "cvc": "123", "cardholder_name": "Dev Team",
}
encrypted = encrypt_card_payload(card, att["encryption_public_key"])

# 3. Send to TEE
resp = requests.post("https://tee-host/billing/card/encrypted", json=encrypted)
print(resp.json())  # {"success": true, "tdx_quote": "..."}
```
