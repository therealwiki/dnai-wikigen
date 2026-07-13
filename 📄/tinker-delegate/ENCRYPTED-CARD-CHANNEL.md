# Encrypted Card Channel Spec

**Status**: Implemented
**Location**: `crypto.py` (134 lines), `card_channel.py` (253 lines)

## Protocol

ECIES-like encryption: X25519 key exchange + HKDF-SHA256 key derivation + AES-256-GCM authenticated encryption.

```
Developer                              TEE (Tinker-Delegate CVM)
   │                                        │
   │──── GET /attestation ─────────────────►│
   │◄─── TDX quote + encryption_pub_key ───│  (X25519 public key)
   │                                        │
   │  1. Verify TDX quote                   │
   │  2. Generate ephemeral X25519 keypair  │
   │  3. ECDH(ephemeral_priv, tee_pub)      │
   │     → shared_secret                    │
   │  4. HKDF-SHA256(shared_secret,         │
   │     info="tinker-delegate-card")       │
   │     → aes_key (256-bit)               │
   │  5. AES-256-GCM(aes_key, nonce,       │
   │     plaintext=CardPayload JSON)        │
   │     → ciphertext + tag                 │
   │                                        │
   │──── POST /billing/card/encrypted ─────►│
   │     {ephemeral_pub_key, nonce,         │  6. ECDH(tee_priv, ephemeral_pub)
   │      ciphertext}                       │     → same shared_secret
   │                                        │  7. HKDF → same aes_key
   │                                        │  8. AES-GCM decrypt
   │                                        │  9. Parse CardPayload JSON
   │                                        │  10. Fill Stripe form via CDP
   │                                        │  11. Zero plaintext from memory
   │◄─── {success, tdx_quote} ─────────────│
```

## What EXISTS

### TEE Side

- `TEEKeyPair` — X25519 keypair generated on boot (not persisted across restarts)
- `TEEKeyPair.decrypt(payload)` — ECDH + HKDF + AES-GCM decrypt
- Singleton pattern via `get_tee_keypair()`
- Full decryption → Stripe form fill → memory zeroing pipeline

### Developer Side

- `encrypt_for_tee(plaintext, tee_public_key)` — generates ephemeral key, ECDH, HKDF, AES-GCM encrypt
- `encrypt_card_payload(card_data, tee_public_key_hex)` — convenience wrapper
- `EncryptedPayload` dataclass with hex serialization

### Wire Format

```json
{
  "ephemeral_public_key": "hex(32 bytes)",
  "nonce": "hex(12 bytes)",
  "ciphertext": "hex(variable — JSON + 16-byte GCM tag)"
}
```

### Cryptographic Parameters

| Parameter | Value | Rationale |
|---|---|---|
| Key exchange | X25519 | Constant-time, no padding oracles |
| KDF | HKDF-SHA256 | Standard, safe salt=None for ephemeral keys |
| HKDF info | `b"tinker-delegate-card"` | Domain separation |
| AEAD | AES-256-GCM | Authenticated encryption, detects tampering |
| Nonce | 12 bytes (96-bit) | Standard GCM nonce size |
| AAD | None | No associated data |

## Known Issues

### 1. No AAD (Associated Authenticated Data)

The `aesgcm.encrypt(nonce, plaintext, None)` call passes `None` as AAD. Adding AAD (e.g., the deal context or a timestamp) would prevent replay attacks where an attacker captures an encrypted card payload and resends it.

**Fix**: Include request metadata as AAD:
```python
aad = json.dumps({"timestamp": time.time(), "purpose": "card-update"}).encode()
ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
```

### 2. Ephemeral TEE Key (Not Persisted)

The X25519 keypair is regenerated on every CVM restart. This means:
- The encryption public key changes between restarts
- The developer must re-fetch `/attestation` after every restart
- Any in-flight encrypted payloads become undecryptable

This is actually a **security feature** — ephemeral keys limit the window for key compromise. But it could cause confusion if the developer caches the public key.

### 3. No TDX Quote Binding for Key

The encryption public key is returned alongside the TDX quote in `GET /attestation`, but the key is not cryptographically bound to the quote. A MITM could potentially replace the key.

**Fix**: Include the public key in the TDX quote's report data:
```python
report_data = f"card-channel:{keypair.public_key_bytes.hex()}"
quote = TappdClient().tdx_quote(report_data)
```

This way, the developer can verify that the public key came from the attested TEE.

### 4. No Nonce Reuse Prevention

The nonce is randomly generated (`os.urandom(12)`). With 96-bit nonces and random generation, the birthday bound is ~2^48 encryptions before collision risk. This is astronomically unlikely for a card update channel (maybe a few operations per month).

## Remaining Work

| Task | Priority | Effort |
|---|---|---|
| Bind public key to TDX quote | High | 30 min |
| Add AAD to prevent replay | Medium | 30 min |
| Developer-side verification library | Medium | 2 hours |
| TDX quote verification (developer tooling) | Medium | 1 day |
| Document key lifecycle (ephemeral, per-boot) | Low | 30 min |

## Trust Analysis

**Why this is safe:**
1. Card details exist in TEE memory for ~10 seconds (fill form → zero)
2. TEE memory is encrypted by TDX — even the hypervisor can't read it
3. Stripe tokenizes the card on their servers — TEE never persists it
4. Developer verifies TDX quote before sending (code measurements match)
5. X25519 ECDH with ephemeral keys provides forward secrecy

**What could go wrong:**
1. Developer skips TDX quote verification → sends card to impostor
2. TEE code has a bug that leaks card data → mitigated by attestation (code is auditable)
3. Stripe iframe changes → billing fails, card details still zeroed
4. TDX vulnerability → entire TEE trust model breaks (not specific to this channel)
