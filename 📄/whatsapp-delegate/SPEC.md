# WhatsApp Data Delegation — Spec, Threat Model & Design Rationale

> **Status**: Draft
> **Date**: 2026-03-11
> **Context**: NDAI / tinker-deligate — attested data delegation
> **Implementation**: `⚙️/whatsapp-delegate`
> **Reference**: TokScope (🔬/amiller), teleport-gramine-rs (🔬/account-link)

---

## 1. Problem

A user's WhatsApp message history is among the most valuable private datasets in existence. It captures years of authentic communication patterns — social graphs, sentiment, decision-making context, interests, schedules, and behavioral fingerprints. This data is enormously useful for ML training, personalized agents, recommendation systems, and research.

But users cannot safely share this data today:

1. **Exfiltration risk**: Once plaintext messages leave the user's device, the user has no control over copies, redistribution, or misuse.
2. **All-or-nothing access**: There's no way to let a pipeline analyze *patterns* without exposing *content*. You can't give a sentiment model access to your messages without also giving it the ability to read and copy every word.
3. **No verifiable computation**: Even if a service promises "we only run sentiment analysis", the user has no way to verify this claim. The service could silently exfiltrate, train on, or sell the raw data.

The NDAI paper (arXiv:2502.07924) addresses exactly this class of problem: how to let a buyer (data consumer) evaluate private information from a seller (data owner) without the seller losing control. The solution is **attested computation inside a TEE**, where the data never leaves the secure boundary and all outputs are bounded.

This document specifies the WhatsApp Data Delegation system: a TEE-based service that logs into WhatsApp Web on behalf of the user, exports their message history, seals it encrypted at rest, and exposes it only through owner-approved, bounded-output pipelines.

---

## 2. Why WhatsApp? Why Is This Hard?

### 2.1 WhatsApp's End-to-End Encryption

WhatsApp uses the Signal Protocol for end-to-end encryption. Messages are encrypted on the sender's device and can only be decrypted by the recipient's device. WhatsApp's servers never see plaintext message content.

This means there is **no server-side API** to fetch message history. Unlike email (IMAP), Twitter (API), or YouTube (Google Takeout), you cannot simply authenticate to a server and download your messages. The messages only exist in plaintext on the devices that participated in the conversation.

### 2.2 Linked Devices — The One Opening

WhatsApp's **Linked Devices** feature (introduced 2021, improved in 2023) creates a multi-device architecture:

- A user can link up to 4 companion devices (web browsers, desktops) to their primary phone
- When a device is linked, WhatsApp syncs **recent message history** to it (currently ~3 months, varies by platform)
- The linked device receives its own copy of the Signal Protocol keys and can independently send/receive messages
- Linked devices work even when the phone is offline

**This is the opening we exploit.** The neko Chrome browser inside the TEE becomes a linked device. WhatsApp syncs message history to it, and the messages appear in the WhatsApp Web DOM in plaintext — where our Playwright automation can extract them.

### 2.3 What You Get From Linking

When a new device is linked, WhatsApp syncs:

| Data | Available | Notes |
|------|-----------|-------|
| Recent messages (text) | Yes | ~90 days, loaded into DOM as you scroll |
| Contact names | Yes | As displayed in chat list |
| Group names & members | Yes | Visible in group info |
| Media (images, video) | Partial | Thumbnails load; full media on-demand |
| Starred messages | Yes | Synced to linked devices |
| Message timestamps | Yes | Relative or absolute depending on recency |
| Read receipts | Yes | Blue ticks visible in DOM |
| Status/Stories | No | Not available on linked devices |
| Archived chats | Yes | Present in chat list |
| Call history | No | Not synced to web |

**Key limitation**: WhatsApp Web only renders messages as you scroll through chats. There's no "export all" button. Our automation must click through each chat and scroll to extract messages — which is exactly what the CDP/Playwright automation does.

### 2.4 Why Not Cloud Backups?

WhatsApp offers encrypted cloud backups (Google Drive / iCloud). Since 2021, users can protect these with a **64-digit encryption key or password**. Could the user just give us the backup password?

Drawbacks of the backup approach:
- **Format**: Backups are in protobuf format (`msgstore.db.crypt15`), requiring reverse-engineering
- **Additional credentials**: Requires the user's Google/iCloud OAuth credentials *in addition to* the backup password — two trust boundaries instead of one
- **Staleness**: Backups are point-in-time snapshots, not live
- **Availability**: Not all users enable cloud backups; backup frequency varies
- **Complexity**: Parsing the protobuf schema correctly is brittle and breaks with WhatsApp updates

The linked-device approach is superior because WhatsApp itself syncs structured, rendered, live data to the browser — we just read the DOM.

---

## 3. Architecture

```
                           ┌─ User's Phone ─┐
                           │                 │
                           │  WhatsApp app   │
                           │  enters linking │
                           │  code: 6NAC-Y7RA│
                           └────────┬────────┘
                                    │ WhatsApp protocol
                                    │ (Signal Protocol, E2EE)
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     TEE ENCLAVE (dstack CVM, Intel TDX)             │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │  Neko Chrome  │◀──│  Delegate    │───▶│  Sealed Store        │  │
│  │  (CDP 9222)  │    │  (FastAPI)   │    │  /data/messages.enc  │  │
│  │              │    │  port 8000   │    │                      │  │
│  │  WhatsApp    │    │              │    │  AES-256-GCM         │  │
│  │  Web session │    │  Playwright  │    │  key = derive_key(   │  │
│  │  (linked     │    │  + CDP       │    │    "whatsapp/msgs")  │  │
│  │   device)    │    │              │    │                      │  │
│  └──────────────┘    └──────┬───────┘    └──────────┬───────────┘  │
│                             │                       │              │
│                             ▼                       ▼              │
│                    ┌──────────────────────────────────────┐        │
│                    │         Pipeline Gate                │        │
│                    │                                      │        │
│                    │  Owner approves:                     │        │
│                    │    sha256:abc... → sentiment model   │        │
│                    │    sha256:def... → topic clusters    │        │
│                    │                                      │        │
│                    │  Bounded outputs ONLY:               │        │
│                    │    ✓ "activity_band: high"           │        │
│                    │    ✓ "sentiment: 60% positive"       │        │
│                    │    ✗ "Alice said: Hey how are..."    │        │
│                    └──────────────────────────────────────┘        │
│                                                                     │
│  dstack.sock → TDX Quote for attestation                            │
│  derive_key("whatsapp/messages") → sealed encryption key            │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.1 Components

| Component | Role | Trust Level |
|-----------|------|-------------|
| **Neko Chrome** | Headful Chrome browser with CDP enabled; becomes a WhatsApp linked device | TEE-internal only |
| **Delegate (FastAPI)** | Orchestrates login flow, drives Playwright automation, manages sealed store and pipeline gate | TEE-internal only |
| **Sealed Store** | AES-256-GCM encrypted message blob; key derived from TEE identity | Encrypted at rest; only this CVM can decrypt |
| **Pipeline Gate** | Access control: maps docker image digests → allowed query types; enforces output bounding | TEE-internal only |
| **dstack KMS** | Provides `derive_key()` for deterministic, TEE-bound encryption keys | Hardware-rooted via Intel TDX |

### 3.2 Network Isolation

All containers run on an isolated Docker bridge network (`172.32.0.0/24`). No container ports are exposed to the internet except through Phala Cloud's TLS gateway. The CDP connection between the delegate and neko Chrome is strictly internal.

---

## 4. Data Flow — Step by Step

### Phase 1: Account Linking

```
User                    Delegate API             Neko Chrome           WhatsApp Servers
  │                         │                        │                       │
  │ POST /login             │                        │                       │
  │ {phone: "+1202..."}     │                        │                       │
  │────────────────────────▶│                        │                       │
  │                         │ navigate to            │                       │
  │                         │ web.whatsapp.com       │                       │
  │                         │───────────────────────▶│                       │
  │                         │                        │ load QR/phone page    │
  │                         │                        │──────────────────────▶│
  │                         │ click "Log in with     │                       │
  │                         │ phone number"          │                       │
  │                         │───────────────────────▶│                       │
  │                         │ fill phone, click Next │                       │
  │                         │───────────────────────▶│                       │
  │                         │                        │ generate linking code │
  │                         │                        │◀──────────────────────│
  │                         │ extract code from DOM  │                       │
  │                         │◀───────────────────────│                       │
  │ {linking_code: "6NAC"}  │                        │                       │
  │◀────────────────────────│                        │                       │
  │                         │                        │                       │
  │ [User enters code on    │                        │                       │
  │  their phone: WhatsApp  │                        │                       │
  │  → Linked Devices →     │                        │                       │
  │  Link → enter code]     │                        │                       │
  │                         │                        │                       │
  │ GET /login/status       │                        │                       │
  │────────────────────────▶│ check for chat list    │                       │
  │                         │───────────────────────▶│                       │
  │ {status: "logged_in"}   │                        │ message sync begins   │
  │◀────────────────────────│                        │◀──────────────────────│
```

**Critical property**: The linking code is ephemeral (expires in ~30 seconds). After linking, the browser session persists as a linked device. The user's WhatsApp password/PIN is never seen by the system — only the one-time linking code passes through.

### Phase 2: Message Export & Sealing

```
User                    Delegate API             Neko Chrome           Sealed Store
  │                         │                        │                       │
  │ POST /export            │                        │                       │
  │ {max_chats: 50}         │                        │                       │
  │────────────────────────▶│                        │                       │
  │                         │ for each chat:         │                       │
  │                         │   click chat item      │                       │
  │                         │   scroll messages      │                       │
  │                         │   extract text + meta  │                       │
  │                         │───────────────────────▶│                       │
  │                         │◀───────────────────────│                       │
  │                         │                        │                       │
  │                         │ WhatsAppExport object  │                       │
  │                         │ (plaintext, in memory) │                       │
  │                         │                        │                       │
  │                         │ seal(export)           │                       │
  │                         │───────────────────────────────────────────────▶│
  │                         │                        │  AES-256-GCM encrypt  │
  │                         │                        │  key = derive_key(    │
  │                         │                        │    "whatsapp/msgs")   │
  │                         │                        │  write messages.enc   │
  │                         │                        │                       │
  │ {sealed: true,          │                        │                       │
  │  messages: 847,         │                        │                       │
  │  chats: 23}             │                        │                       │
  │◀────────────────────────│                        │                       │
```

**After sealing**: The plaintext export is released from memory. The only copy of the data exists in `/data/messages.enc`, encrypted with a key that only this specific CVM can derive. Even if the encrypted file is exfiltrated, it cannot be decrypted without the TEE's identity.

### Phase 3: Bounded Pipeline Access

```
Pipeline                Delegate API             Pipeline Gate         Sealed Store
  │                         │                        │                       │
  │ POST /pipeline/query    │                        │                       │
  │ {digest: "sha256:abc",  │                        │                       │
  │  type: "aggregate"}     │                        │                       │
  │────────────────────────▶│                        │                       │
  │                         │ verify digest approved │                       │
  │                         │───────────────────────▶│                       │
  │                         │ verify query type in   │                       │
  │                         │ allowed_outputs        │                       │
  │                         │◀───────────────────────│                       │
  │                         │                        │                       │
  │                         │ unseal(messages.enc)   │                       │
  │                         │───────────────────────────────────────────────▶│
  │                         │◀───────────────────────────────────────────────│
  │                         │                        │                       │
  │                         │ apply bounding:        │                       │
  │                         │   raw counts → bands   │                       │
  │                         │   names → yes          │                       │
  │                         │   text → NEVER         │                       │
  │                         │ cap output tokens      │                       │
  │                         │                        │                       │
  │ {result: {              │                        │                       │
  │    total_band: "high",  │                        │                       │
  │    per_chat: [...]},    │                        │                       │
  │  bounded: true}         │                        │                       │
  │◀────────────────────────│                        │                       │
```

---

## 5. Trust Model & Threat Analysis

### 5.1 What the User Trusts

| Trust Assumption | Justification |
|------------------|---------------|
| The TEE code is what the attestation claims | Open source + reproducible build + TDX quote verification |
| The TEE hardware is not compromised | Intel TDX with remote attestation; Phala Cloud infrastructure |
| WhatsApp's linked device protocol is secure | Signal Protocol E2EE; WhatsApp's own security guarantees |
| The pipeline gate enforces output bounds | Code is auditable; output bounding is structural, not policy-based |

### 5.2 What the User Does NOT Need to Trust

| No Trust Required | Why |
|-------------------|-----|
| The service operator | TEE attestation proves the code is unmodified; operator cannot read sealed data |
| The pipeline developer | Pipeline is identified by docker image digest; only pre-approved queries execute |
| The network | All data is encrypted in transit (TLS) and at rest (AES-256-GCM) |
| The storage layer | Sealed data is encrypted with TEE-derived keys; cloud storage sees only ciphertext |

### 5.3 Threat Matrix

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| **Operator steals messages** | Messages sealed with `derive_key("whatsapp/messages")`; operator has no access to TEE memory | Side-channel attacks on TDX (theoretical, no known practical exploits) |
| **Pipeline exfiltrates raw text** | Pipeline never receives raw text; only bounded aggregates pass through the gate | A malicious pipeline could encode information in query patterns over time (rate-limiting needed) |
| **Replay of linking code** | Linking codes expire in ~30 seconds; each code is one-time-use | None — WhatsApp enforces this server-side |
| **Persistent WhatsApp session hijack** | Session exists only inside TEE; user can unlink device from WhatsApp settings at any time | If TEE is compromised, attacker has active WhatsApp session until user unlinks |
| **Encrypted file exfiltration** | AES-256-GCM with TEE-derived key; file is useless without the exact same CVM identity | If TDX key derivation is broken, historical sealed data could be decrypted |
| **DOM scraping misses messages** | Playwright automation scrolls and extracts; coverage depends on WhatsApp Web rendering | Very old messages may not sync to linked devices; media content not fully captured |
| **WhatsApp detects automation** | Browser runs in neko (headful, real Chrome, real user-agent); no detectable automation signals | WhatsApp could add anti-automation measures in future versions |
| **Output bounding is too coarse** | Banding system (low/medium/high) prevents exact reconstruction; output token cap limits total information | Repeated queries with different parameters could narrow estimates (rate-limiting needed) |

### 5.4 What Happens If the User Wants Out

The user has multiple exit paths:

1. **Unlink the device**: WhatsApp → Settings → Linked Devices → remove the browser session. The TEE immediately loses access to new messages.
2. **DELETE /data**: The owner calls the delete endpoint, which overwrites the sealed file with random bytes before unlinking — irrecoverable destruction.
3. **Revoke all pipelines**: `POST /pipeline/revoke` removes all approved pipelines. No queries can execute.
4. **CVM shutdown**: If the Phala Cloud CVM is stopped, the session and sealed data become inaccessible (key derivation requires the running CVM).

---

## 6. Sealed Storage Design

### 6.1 Encryption

| Property | Value |
|----------|-------|
| Algorithm | AES-256-GCM |
| Nonce | 12 bytes, random per seal |
| Key source (TEE) | `dstack_sdk.derive_key("whatsapp/messages")` |
| Key source (local dev) | Auto-generated, persisted to `.key` file |
| File format | `[nonce:12 bytes][ciphertext+tag]` |
| Location | `/data/messages.enc` |

### 6.2 Key Derivation Properties

In dstack TEE mode, `derive_key(path)` is deterministic per CVM identity:

- **Same CVM, same path → same key**: Data survives CVM restarts
- **Different CVM, same path → different key**: Data cannot be migrated to a different CVM
- **Same CVM, different path → different key**: WhatsApp keys are isolated from email keys, card keys, etc.

This means the sealed WhatsApp data is **bound to the specific CVM instance** that created it. Even the service operator running a different CVM with the same code cannot decrypt data from another CVM.

### 6.3 Data Lifecycle

```
1. Export    → plaintext in memory (seconds)
2. Seal      → AES-256-GCM encrypted to /data/messages.enc
3. At rest   → only this CVM can unseal
4. Query     → unseal in memory, compute bounded result, release
5. Delete    → overwrite with random bytes, then unlink
```

Plaintext only exists in TEE memory during steps 1, 2, and 4. It is never written to disk unencrypted, never transmitted over the network, and never logged.

---

## 7. Output Bounding — The NDAI Principle

The NDAI paper establishes that pipeline outputs must be **bounded** to prevent information reconstruction. Raw data must never leave the TEE. Instead, all outputs are coarsened to prevent exact reconstruction.

### 7.1 Banding System

Exact message counts are mapped to coarse bands:

| Count | Band |
|-------|------|
| 0 | none |
| 1–100 | low |
| 101–1,000 | medium |
| 1,001–10,000 | high |
| 10,001+ | very_high |

An observer who sees `"activity_band": "medium"` for contact "Alice" learns only that there are between 101 and 1,000 messages — not the exact count.

### 7.2 Supported Query Types

| Query | Output | What's Bounded |
|-------|--------|----------------|
| `aggregate_counts` | Total messages (banded), per-chat activity bands | Exact counts → bands |
| `activity_timeline` | Hourly message distribution (counts per hour) | Content → dropped; only timing patterns |
| `contact_summary` | Contact names + activity bands | Message content → dropped |
| `sentiment_bands` | Coarse sentiment distribution (short/medium/long) | Actual text → dropped; placeholder for real ML |
| `topic_clusters` | Category labels only | Text excerpts → dropped; placeholder for real NLP |

### 7.3 Output Size Cap

All pipeline outputs are capped at `MAX_OUTPUT_TOKENS = 4096` characters. Any result exceeding this limit is rejected. This prevents a pipeline from encoding raw messages into a large output payload.

### 7.4 What's NOT Possible Through the Gate

| Operation | Possible? | Why Not |
|-----------|-----------|---------|
| Read raw message text | No | Text fields are never included in any query response |
| Get exact message counts | No | All counts are banded |
| Download the sealed file | No | Only unseal-in-memory + bounded query is exposed |
| Query without approval | No | Pipeline digest must be pre-approved by data owner |
| Query unapproved output types | No | Each pipeline approval specifies which query types are allowed |
| Reconstruct messages from queries | Impractical | Banding + output cap + no text content makes reconstruction infeasible |

---

## 8. Comparison to Prior Art

### 8.1 TokScope (Account-Link / Flashbots)

TokScope (🔬/amiller/devproof-audits-guide/case-studies/tokscope-xordi/) captures TikTok sessions in a TEE:

| Aspect | TokScope | WhatsApp Delegate |
|--------|----------|-------------------|
| Platform | TikTok | WhatsApp |
| Auth method | QR code login | Phone number + linking code |
| Data captured | Session cookies for API access | DOM-extracted messages |
| Storage | Encrypted cookies via Xordi API | Local sealed store (AES-256-GCM) |
| Output control | API-mediated access | Pipeline gate with bounded outputs |
| TEE | dstack (Phala Cloud) | dstack (Phala Cloud) |

WhatsApp Delegate improves on TokScope by adding **owner-controlled pipeline approval** and **structural output bounding** (the NDAI contribution).

### 8.2 teleport-gramine-rs (Account-Link)

Teleport (🔬/account-link/teleport-gramine-rs/) implements one-time-use credential delegation via SGX NFTs:

| Aspect | Teleport | WhatsApp Delegate |
|--------|----------|-------------------|
| Delegation model | NFT-based one-time credentials | Linked device session |
| Policy enforcement | LLM safeguards on posting | Pipeline gate with bounded queries |
| On-chain component | NFT minting + trading | Not yet (future: escrow contract) |
| TEE | SGX (Gramine) | Intel TDX (dstack) |

### 8.3 "Your Shell or Mine" (oauth3-openclaw)

The PRD in 🔬/amiller/oauth3-openclaw/ envisions a general framework for private data queries:

> "You have private data that's valuable to others — Claude Code interaction logs, YouTube watch history, search history, email, browser history, git diffs. You can't just hand it over. But you could let people *query* it, if you could guarantee: the query code only returns aggregates (never raw records), and the results are authentic (not fabricated)."

WhatsApp Delegate is a concrete implementation of this vision, specialized for WhatsApp messages.

---

## 9. Limitations & Future Work

### 9.1 Current Limitations

1. **Message coverage**: WhatsApp Web syncs ~90 days of history. Older messages are not available through the linked device mechanism.
2. **Media**: Images, videos, and voice notes are not extracted (only text messages).
3. **Selector fragility**: WhatsApp Web's DOM structure can change with updates, breaking Playwright selectors. Selectors need periodic maintenance.
4. **Rate limiting**: No rate limiting on pipeline queries yet. A malicious approved pipeline could make many queries to narrow banding estimates.
5. **No on-chain escrow**: Unlike the tinker-delegate, there's no smart contract governing the data access terms. Pipeline approval is purely API-based.

### 9.2 Planned Improvements

1. **ML pipeline execution inside TEE**: Instead of bounded query types, allow approved docker images to run arbitrary ML models inside the TEE, with only bounded outputs leaving. This enables real sentiment analysis, topic modeling, and fine-tuning.
2. **Escrow contract**: On-chain deal structure where the data consumer stakes funds, the pipeline runs in the TEE, and bounded results are submitted with a TDX attestation quote.
3. **Continuous sync**: Keep the linked device session alive and incrementally update the sealed store as new messages arrive.
4. **Multi-platform**: Extend the delegation pattern to other messaging platforms (Telegram, Signal, iMessage via iCloud backup decryption).
5. **Differential privacy**: Add formal differential privacy guarantees to pipeline outputs, providing mathematical bounds on information leakage.
6. **Query rate limiting**: Cap the number of pipeline queries per time period to prevent statistical narrowing of banded outputs.

---

## 10. API Reference

### Authentication & Linking

| Endpoint | Method | Input | Output |
|----------|--------|-------|--------|
| `POST /login` | Start WhatsApp Web login | `{phone_number: "+1..."}` | `{status, linking_code, detail}` |
| `GET /login/status` | Poll: has the phone linked? | — | `{status: "waiting"\|"logged_in"}` |
| `POST /login/wait` | Block until linked or timeout | `{timeout_seconds: 120}` | `{status: "logged_in"}` or 408 |

### Data Export

| Endpoint | Method | Input | Output |
|----------|--------|-------|--------|
| `POST /export` | Scrape chats, seal to encrypted store | `{max_chats: 50}` | `{total_messages, total_chats, phone}` |
| `GET /status` | Check sealed data + pipeline state | — | `{sealed_data_exists, approved_pipelines}` |
| `DELETE /data` | Owner destroys sealed data | — | `{status: "destroyed"}` |

### Pipeline Management

| Endpoint | Method | Input | Output |
|----------|--------|-------|--------|
| `POST /pipeline/approve` | Owner approves a pipeline | `{image_digest, description, allowed_outputs}` | `{status: "approved"}` |
| `POST /pipeline/revoke` | Owner revokes a pipeline | `{image_digest}` | `{status: "revoked"}` |
| `GET /pipeline/list` | List approved pipelines | — | `{pipelines: [...]}` |
| `POST /pipeline/query` | Pipeline queries bounded data | `{pipeline_digest, query_type, params}` | `{result, bounded: true}` |

### Debug & Attestation

| Endpoint | Method | Output |
|----------|--------|--------|
| `GET /health` | Liveness check | `{status: "ok", cdp_url, dstack}` |
| `GET /screenshot` | Debug: browser screenshot | PNG image |
| `GET /attestation` | TDX attestation quote | `{attestation: "..."}` or null |
