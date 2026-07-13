# TEE Email Oracle — Spec & Threat Model

> **Status**: Draft
> **Date**: 2026-03-08
> **Context**: NDAI / tinker-deligate hackathon
> **Provider**: cock.li (decided — see PROVIDER-COMPARISON.md)

## 1. Problem

Many services require email-based verification (pins, OTPs, magic links) during
signup or login. If a human holds the email credentials, they can intercept
these codes — breaking the trust boundary of any TEE-based agent system.

We need an email account that:

1. Is **created inside a TEE** — credentials never touch human hands
2. Has **no recovery path** — no human can ever regain access
3. Can **securely deliver verification pins** to other trusted dstack apps
4. Is **verifiable** — anyone can confirm only the attested code has access

This is the "Setting Your Pet Rock Free" pattern applied to email.

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                 dstack CVM (Intel TDX)                       │
│                                                              │
│  ┌────────────────────┐    ┌──────────────────────┐         │
│  │  email-oracle       │    │  neko browser         │        │
│  │  (Python)           │───▶│  (chromium container)  │       │
│  │                     │    │  signup only — then    │        │
│  │  - IMAP client      │    │  stopped               │        │
│  │  - captcha solver   │    └──────────────────────┘         │
│  │  - pin extraction   │                                     │
│  │  - attestation API  │                                     │
│  └────────┬───────────┘                                      │
│           │                                                  │
│  ┌────────▼───────────┐                                      │
│  │  dstack-KMS         │  key = derive_key("email/creds")    │
│  │  (sealed storage)   │  same app_id → same key on reboot   │
│  └────────────────────┘                                      │
│                                                              │
│  tappd.sock → TDX Quote on every response                    │
└──────────────────────────────────────────────────────────────┘
         │
         │  mTLS + TDX quote verification
         ▼
┌────────────────────────┐
│  Consumer dstack app   │  e.g. signup-agent, auth-agent
│  (separate CVM)        │  requests: "get me the pin from
│                        │   sender X, subject matching Y"
└────────────────────────┘
```

## 3. Components

### 3.1 Account Creator (one-shot, then discarded)

**Runtime**: neko browser (headless chromium) inside the CVM.

**Provider**: cock.li — plain HTML form, no SPA, no phone verification,
no recovery mechanism, free forever, standard IMAP. Captcha fully solved
with CPU-only template matching (see `⚙️/tee-email-oracle/captcha-solver/`).

**Flow**:

1. Generate credentials inside TEE:
   - Username: `crypto.randomBytes(8).toString('hex')` → e.g. `a3f8c1d9`
   - Domain: `firemail.cc` (presentable) or random from 15 available
   - Password: `crypto.randomBytes(32).toString('base64url')` — 256-bit
2. Fetch registration page (`https://cock.li/register.php`)
3. Solve CSS box-shadow captcha via template matching (~2ms, CPU-only)
4. Submit form with username, domain, password, captcha solution, CSRF token
5. Encrypt and store credentials via `derive_key("email/creds")`
6. Stop neko browser container — it is never started again
7. Generate TDX attestation quote binding the new email address to report_data

| Reason | Detail |
|--------|--------|
| Plain HTML form | No SPA, no JS framework — simplest CDP automation |
| Captcha solved | CSS pixel art parsed from HTML, template-matched at 100% accuracy |
| Standard IMAP | `mail.cock.li:993` — any IMAP library works, no Bridge/proxy |
| No phone ever | Not even from datacenter IPs — critical for Phala Cloud |
| No recovery exists | Account permanently locked to TEE-sealed password |
| Free forever | No payment, no trial expiry, no account suspension risk |
| TEE precedent | Used by TEE_HEE (Nous/Flashbots) for same purpose |
| 15 domains | `firemail.cc`, `airmail.cc` for presentable addresses |

**Alternatives considered** (see PROVIDER-COMPARISON.md for full analysis):

- **Fastmail**: Best API (JMAP with scoped tokens) but requires payment,
  SPA signup, SMS verification risk from datacenter IPs. Premium fallback
  if IMAP proves insufficient.
- **Proton**: Phone verification triggered from datacenter IPs (hard blocker).
  No IMAP without Bridge desktop app.
- **Tuta**: No IMAP/SMTP/API at all (absolute blocker). 6-month inactivity deletion.
- **Migadu**: REST API for mailbox creation (no browser needed), standard IMAP,
  but requires bringing your own domain.
- **Self-hosted Stalwart**: Full JMAP+IMAP, zero third-party trust, but
  significant ops burden and requires a domain + IP with clean mail reputation.

### 3.2 Email Oracle (long-running service)

**Runtime**: Python (uv + pyproject.toml) inside the same CVM.

**Responsibilities**:
- Hold encrypted credentials (decrypt via dstack-KMS on boot)
- Poll inbox via IMAP (`mail.cock.li:993`, TLS)
- Extract verification pins/codes from emails matching caller-specified filters
- Serve an attestation-authenticated API

**API**:

```
POST /pin
Authorization: Bearer <tee-derived-token>
X-TDX-Quote: <caller's quote for mutual attestation>

{
  "from": "noreply@service.com",
  "subject_contains": "verification",
  "max_age_seconds": 300,
  "extract_pattern": "\\b\\d{6}\\b"
}

→ 200 OK
{
  "pin": "482917",
  "email_id": "12345",
  "received_at": "2026-03-07T12:34:56Z",
  "tdx_quote": "<oracle's quote binding this response>"
}
```

**IMAP query** (executed inside TEE):

```python
import imaplib
import email
import re

mail = imaplib.IMAP4_SSL('mail.cock.li', 993)
mail.login(username, password)
mail.select('INBOX')

# Search for recent emails matching sender filter
cutoff = (datetime.utcnow() - timedelta(seconds=max_age)).strftime('%d-%b-%Y')
_, ids = mail.search(None, f'FROM "{from_filter}" SINCE "{cutoff}"')

for msg_id in ids[0].split():
    _, data = mail.fetch(msg_id, '(RFC822)')
    msg = email.message_from_bytes(data[0][1])

    # Check subject filter
    if subject_contains and subject_contains not in msg['Subject']:
        continue

    # Extract body text
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body = part.get_payload(decode=True).decode()
                break
    else:
        body = msg.get_payload(decode=True).decode()

    # Extract pin
    match = re.search(extract_pattern, body)
    if match:
        return match.group()
```

### 3.3 Cross-App Authentication

Two dstack apps cannot share derived keys (different `app_id`). Secret
delivery uses **mutual TDX attestation over TLS**:

```
Consumer App                          Email Oracle
     │                                     │
     ├─ Generate TDX quote ───────────────▶│
     │  (report_data = nonce)              │
     │                                     ├─ Verify quote:
     │                                     │   - DCAP signature valid?
     │                                     │   - MRTD matches allowed list?
     │                                     │   - RTMRs match expected code?
     │                                     │
     │◀── TDX quote + encrypted pin ──────┤
     │   (report_data = sha256(pin+nonce)) │
     │                                     │
     ├─ Verify oracle's quote              │
     ├─ Decrypt pin                        │
     └─ Use pin for signup/login           │
```

**Allowed consumer list**: The email oracle maintains an on-chain or
config-embedded allowlist of `(compose_hash, deployer_id)` tuples.
Only consumers whose MRTD/RTMRs match an allowed entry receive pins.

**Alternative (same compose file)**: If consumer and oracle are services
within the same `docker-compose.yaml`, they share the same `app_id` and
can use `derive_key("shared/secret")` for a symmetric key. Simpler but
couples deployment.

## 4. Threat Model

### 4.1 Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│  TRUSTED                                        │
│                                                 │
│  - Code running inside TDX CVM                  │
│  - dstack-KMS MPC nodes (each in TEE)           │
│  - Intel TDX hardware (CPU package)             │
│  - On-chain AppAuth contract logic              │
│                                                 │
├─────────────────────────────────────────────────┤
│  UNTRUSTED                                      │
│                                                 │
│  - Cloud provider (Phala) — can see metadata,   │
│    encrypted traffic, cannot read TD memory     │
│  - dstack operator — cannot extract keys,       │
│    cannot deploy unauthorized code              │
│  - Network observers — see encrypted traffic    │
│  - Human deployers — no SSH, no console,        │
│    no memory inspection                         │
│                                                 │
├─────────────────────────────────────────────────┤
│  PARTIALLY TRUSTED                              │
│                                                 │
│  - Email provider (cock.li) — CAN read email    │
│    contents at rest. Cannot access TEE memory   │
│    or extract stored credentials.               │
│    Mitigation: pins are short-lived, extracted   │
│    immediately, and the inbox is ephemeral.     │
│                                                 │
│  - Intel (CPU vendor) — theoretically could     │
│    extract fused keys with physical die access.  │
│    No demonstrated TDX key extraction attack.    │
│    Mitigated by MPC-distributed root key.       │
│                                                 │
└─────────────────────────────────────────────────┘
```

### 4.2 Threat Matrix

| # | Threat | Attacker | Impact | Mitigation |
|---|--------|----------|--------|------------|
| T1 | Extract email credentials from TEE memory | Cloud provider / root on host | Full account takeover | TDX encrypts TD memory with per-TD AES-XTS 128-bit key. Hypervisor removed from trust boundary. Host reads cause page faults. |
| T2 | Deploy malicious code to extract credentials | Compromised developer | Credential exfiltration | AppAuth contract requires multi-sig approval for code upgrades. dstack-KMS only provisions keys to authorized compose hashes. |
| T3 | Recover email account via provider support | Social engineering attacker | Account takeover | cock.li has no recovery mechanism at all — no recovery email, phone, security questions, or backup codes. Provider cannot reset. |
| T4 | Intercept pin in transit between TEE apps | Network observer / cloud provider | Pin theft | Mutual TDX attestation + TLS. Pin encrypted to consumer's TEE-derived public key. Network sees only ciphertext. |
| T5 | Replay a previously captured pin | Attacker with network access | Unauthorized login | Pins are single-use and short-lived (typically 5-10 min). Oracle tracks delivered pin IDs and rejects re-requests for same email_id. |
| T6 | Impersonate a consumer app to request pins | Rogue dstack app | Pin theft | Consumer must present valid TDX quote. Oracle verifies MRTD/RTMRs against allowlist. Unauthorized code produces wrong measurements. |
| T7 | Email provider reads inbox contents | cock.li (insider/compelled) | Pin interception | cock.li CAN read emails. Mitigation: pins are short-lived, oracle extracts within seconds, inbox is ephemeral. For higher assurance, swap to self-hosted Stalwart. |
| T8 | TDX side-channel attack (TDXdown) | Co-tenant on same host | Key leakage via timing | Patched in TDX module 1.5.06. dstack pins TDX module version. OpenSSL/wolfSSL patched for nonce leakage. |
| T9 | TDX live migration TOCTOU (CVE-2025-30513) | Malicious host during migration | Full TD state exposure | Patched by Intel. dstack can disable live migration. Phala does not enable migration by default. |
| T10 | TEE crashes, credentials lost | Hardware failure | Permanent lockout from email | dstack-KMS derives keys deterministically from RootKey. On reboot, same `app_id` re-derives same keys. Encrypted disk persists across crashes. |
| T11 | dstack-KMS MPC compromise | Colluding MPC operators | Root key exposure, all app keys compromised | MPC threshold (e.g. 3-of-5) requires multiple independent compromises. Each MPC node runs in a TEE. Geographic and organizational distribution. |
| T12 | Sender spoofs verification email | Attacker sending fake pin emails | Consumer uses wrong pin | Oracle filters by exact sender address + subject pattern. Consumer specifies expected sender. cock.li relies on upstream DKIM/SPF checks. |

### 4.3 What We Explicitly Do NOT Protect Against

- **Email provider reading email contents** (T7). cock.li is not end-to-end
  encrypted. They can read pins. We accept this because: pins expire in
  minutes, the oracle extracts them in seconds, and the account is otherwise
  inaccessible to humans. For higher assurance, swap cock.li for self-hosted
  Stalwart (eliminates this threat entirely).

- **Intel hardware backdoors**. If Intel has an undisclosed mechanism to
  extract TDX memory encryption keys from the CPU die, all bets are off.
  This is a shared assumption across the entire TEE ecosystem. Mitigated
  partially by MPC-distributed root key (compromising one CPU doesn't
  compromise the KMS root).

- **Email account suspension by provider**. cock.li can suspend or delete
  the account. Mitigation: don't violate ToS, monitor account health from
  within the TEE. cock.li has no inactivity deletion policy and is free,
  so payment lapse is not a risk. If suspended, the email address is lost
  but no credentials are exposed.

- **Email deliverability**. cock.li domains may be blocked by some services
  that reject mail from these domains. Use `firemail.cc` or `airmail.cc`
  for better deliverability. If a target service rejects cock.li domains
  entirely, the oracle cannot receive verification emails from that service.

## 5. Credential Lifecycle

```
PHASE 1: GENESIS (one-shot, ~30 seconds)
═══════════════════════════════════════
  TEE boots → fetch cock.li/register.php
  → generate random username + password inside enclave
  → solve CSS captcha via template matching (~2ms)
  → submit registration form via HTTP POST
  → verify account created (check IMAP login)
  → seal credentials via derive_key("email/creds")
  → emit TDX attestation binding email address

  Note: neko browser only needed if HTTP POST signup fails
  and we must fall back to full browser automation.

PHASE 2: OPERATION (long-running)
═════════════════════════════════
  TEE boots → decrypt credentials via derive_key("email/creds")
  → connect IMAP client to mail.cock.li:993
  → listen for pin requests on attestation API
  → on request: verify consumer TDX quote → poll inbox via IMAP
  → extract pin → return pin + oracle TDX quote
  → delete read emails (optional, reduces exposure window)

PHASE 3: KEY ROTATION (periodic)
════════════════════════════════
  (Same app_id, upgraded code authorized by AppAuth contract)
  → new code re-derives same keys
  → rotates email password via cock.li change-password form
  → updates sealed store
  → old code version deauthorized on-chain

PHASE 4: END OF LIFE
════════════════════
  Deauthorize app on AppAuth contract
  → KMS stops provisioning keys
  → credentials become irrecoverable
  → email account abandoned (no human can access it either)
```

## 6. Implementation Plan

### Phase 1: Proof of Concept (local, no TEE)

Build the core without TEE to validate the email automation flow:

- [x] **captcha solver** — CPU-only template matching for cock.li CSS
      box-shadow captcha. 100% accuracy, ~2ms solve time.
      Code: `⚙️/tee-email-oracle/captcha-solver/`
- [ ] **account creator** — Python script that fetches registration page,
      solves captcha, submits form via HTTP POST, verifies IMAP login
- [ ] **email-oracle service** — Python (uv/pyproject.toml), IMAP client
      that authenticates to cock.li, polls inbox, extracts pins via regex
- [ ] **credential store** — file-based encrypted store (AES-256-GCM with
      key from env var, simulating dstack-KMS `derive_key`)
- [ ] **pin extraction API** — HTTP server with `/pin` endpoint, no auth
      (mocked consumer for testing)
- [ ] **docker-compose.yaml** — oracle service (+ optional neko browser
      for fallback signup automation)

### Phase 2: TEE Integration

- [ ] Replace file-based key with `dstack_sdk.TappdClient.derive_key("email/creds")`
- [ ] Add TDX quote generation on every `/pin` response
- [ ] Add consumer quote verification on every `/pin` request
- [ ] Compose hash pinning + AppAuth contract deployment
- [ ] dstack-compatible `docker-compose.yaml` with `tappd.sock` mount
- [ ] Attestation endpoint (`GET /attestation`) returning current TDX quote

### Phase 3: Cross-App Integration

- [ ] Define allowlist format for authorized consumer apps
- [ ] Implement mutual attestation handshake
- [ ] Build reference consumer (e.g. a signup-agent that uses the email
      oracle to complete email verification on a third-party service)
- [ ] On-chain AppAuth governance for code upgrades

## 7. Open Questions

1. ~~**Provider selection**~~: **Decided: cock.li.** See PROVIDER-COMPARISON.md.

2. ~~**Same-compose vs cross-compose**~~: **Decided: cross-compose.**
   Oracle and consumers run in separate CVMs with separate `app_id`s.
   Stronger isolation, consumer auth via mutual TDX attestation +
   on-chain allowlist. See `CONTRACT-SPEC.md` for consumer auth design.

3. **Email retention**: Should the oracle delete emails after extracting
   pins? Reduces exposure window but loses audit trail.

4. ~~**Payment**~~: **Not needed.** cock.li is free forever.

5. ~~**Browser automation reliability**~~: **Mostly eliminated.** cock.li's
   plain HTML form can be submitted via HTTP POST — no browser needed for
   the primary path. Neko browser kept as fallback only.

6. **Pin delivery guarantee**: What if the pin email hasn't arrived yet
   when the consumer requests it? IMAP IDLE for push notification, or
   polling with exponential backoff and timeout?

7. ~~**Deliverability**~~: **Resolved for our use case.** The only target
   service is Thinking Machines Tinker. Recon confirmed `cock.email`
   domain passes their blocklist (`cock.li` and `firemail.cc` are blocked).
   Default domain config should be `cock.email` for Tinker deployments.
   General deliverability to other services is out of scope.

## 8. References

| Resource | URL |
|----------|-----|
| DelegaTEE paper (USENIX 2018) | https://www.usenix.org/conference/usenixsecurity18/presentation/matetic |
| Setting Your Pet Rock Free (Nous) | https://nousresearch.com/setting-your-pet-rock-free/ |
| dstack KMS protocol | https://docs.phala.com/dstack/design-documents/key-management-protocol |
| dstack SDK (Python) | https://pypi.org/project/dstack-sdk/ |
| cock.li | https://cock.li |
| cock.li captcha solver | `⚙️/tee-email-oracle/captcha-solver/` |
| Provider comparison | `📄/tee-email-oracle/PROVIDER-COMPARISON.md` |
| TDXdown attack | https://uzl-its.github.io/tdxdown/ |
| CVE-2025-30513 (TDX migration) | https://www.securityweek.com/google-intel-security-audit-reveals-severe-tdx-vulnerability-allowing-full-compromise/ |
| Loose SEAL (SGX sealing for TDX) | https://collective.flashbots.net/t/loose-seal-enabling-crash-tolerant-tdx-applications-by-utilizing-sgx-sealing-provider-sidecar/4243 |
| Replicatoor (secret migration) | https://collective.flashbots.net/t/replicatoor-upgrade-controlled-migration-module-for-dstack/4148 |
| amiller/teemail | https://github.com/amiller/teemail |
| Account-Link/neko_agent | https://github.com/Account-Link/neko_agent |
