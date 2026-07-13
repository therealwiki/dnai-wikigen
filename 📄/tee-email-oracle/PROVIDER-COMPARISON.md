# Email Provider Comparison for TEE Account Delegation

> **Decision**: cock.li
> **Date**: 2026-03-08
> **Captcha**: SOLVED — CSS template matching, 100% accuracy

## Context

We need an email provider where:

1. An account can be **created entirely inside a TEE** (automated signup)
2. Credentials are **sealed** — no human can ever recover the account
3. The TEE can **read incoming emails programmatically** (to extract verification pins)
4. **No phone number or existing email** is required for signup
5. **No recovery mechanism** exists that a human could use to regain access

This email account acts as an oracle — other trusted dstack apps request
verification pins from it over mutually-attested TLS channels.

---

## Providers Evaluated

### 1. cock.li

**Homepage**: https://cock.li
**Registration**: https://cock.li/register.php

#### Signup Form (inspected live via CDP)

Plain HTML `<form method="POST">`. No SPA framework, no JavaScript required
beyond captcha rendering.

```
Fields:
  input[name="csrf"]              hidden, CSRF token (unquoted value)
  input[name="username"]          text, the local part
  select[name="domain"]           15 domain options
  input[name="password"]          password
  input[name="password_confirm"]  password confirmation
  input[name="captcha_key"]       hidden, server-generated key (single-quoted)
  input[name="captcha_solution"]  text, user solves captcha
  input[name="tos_agree"]         checkbox, ToS agreement
  input[name="news_subscribe"]    checkbox, newsletter (optional)
  button "Register"               submit
```

#### Available Domains (15)

```
cock.li          airmail.cc        420blaze.it
aaathats3as.com  cumallover.me     horsefucker.org
national.shitposting.agency       nigge.rs
tfwno.gf         cock.lu           cock.email
firemail.cc      memeware.net      cocaine.ninja
waifu.club
```

For professional use: `firemail.cc` and `airmail.cc` are presentable.

#### Protocol Support

| Protocol | Server | Port |
|----------|--------|------|
| IMAP | mail.cock.li | 993 (TLS) |
| POP3 | mail.cock.li | 995 (TLS) |
| SMTP | mail.cock.li | 587 (STARTTLS) |
| Webmail | mail.cock.li | 443 |
| Tor hidden service | (onion address) | all protocols |

#### Captcha — SOLVED

The captcha is **not a traditional image**. It is **CSS pixel art** rendered
via `box-shadow` properties on ~39 `<div>` elements inside the HTML form.

**How it works:**

Each div has a style like:
```
style='float:right;clear:both;width:1px;height:0;margin-right:120px;
       box-shadow:#000000 0px 0px 1px 1px,#f0dcc8 5px 0px 1px 1px,...'
```

Each `box-shadow` entry paints a single pixel at `(X, Y)` with a specific
color. Together they form a 99x39 pixel grid showing 5-6 alphanumeric
characters in a fixed-width bitmap font (light text on black background).

**Solver approach: CPU-only template matching**

| Step | Detail |
|------|--------|
| Parse | Regex-extract `(x, y, #color)` tuples from CSS `box-shadow` |
| Reconstruct | Build 99x39 PIL Image from pixel data |
| Binarize | Threshold > 80 = text pixel, else background |
| Segment | Split characters by column gaps (every char is exactly 10px wide, 1px gaps) |
| Match | Hamming distance against stored 10x24 bitmap templates |
| Fallback | Tesseract OCR for any character not in template DB |

**Results:**

- **100% solve rate** on 21 consecutive fresh captchas (final blind validation)
- **0 unknowns** in last 39 consecutive successful fetches
- **49 unique characters** covered (60 templates with variants)
- **~2ms per solve** — pure pixel comparison, no ML inference
- CPU-only: `pillow` + `pytesseract` (fallback). No GPU, no neural networks.
- Missing 13 rare/unused chars: `0 5 B H L Q T W c h m n s`

**Why Tesseract alone failed (~37% accuracy):**

The pixel font confuses Tesseract's LSTM model (trained on smooth text).
Common misreads: `9→d`, `8→S`, `1→l`, `M→H`, `7→r`. Template matching
gives exact distance-0 matches because the font is fixed.

**Integration:**

```python
# From raw HTML (CDP / httpx / Playwright page.content())
from captcha_solver import solve_from_html
solution = solve_from_html(html)

# Full flow: HTTP fetch + parse + solve + extract form tokens
from captcha_solver.fetcher import fetch_and_solve
solution, captcha_key, csrf = fetch_and_solve()
```

Code lives at: `📄/tee-email-oracle/captcha-solver/`

#### Recovery

**None**. No recovery email, no recovery phone, no backup codes, no security
questions. If you lose the password, the account is gone. This is a feature
for our use case.

#### Account Deletion Policy

No automatic deletion for inactivity. Accounts persist indefinitely.

#### Reputation & Precedent

- **Used by TEE_HEE** (Nous Research / Teleport) for the "Setting Your Pet
  Rock Free" autonomous AI agent. Andrew Miller's `cucumber-twitter2` repo
  demonstrates browser-based account delegation using the same stack.
- Running since 2013, 1M+ users.
- Warrant canary and transparency reports published.
- Explicitly states: "You will never be asked to verify personal information."

#### CDP Automation Difficulty: **EASIEST**

Standard HTML form POST. No SPA hydration, no client-side routing, no
framework state management. Playwright/browser-use can fill and submit
in a single pass. Captcha is fully solved.

---

### 2. Proton Mail

**Homepage**: https://proton.me
**Registration**: https://account.proton.me/signup

#### Signup Form (inspected live via CDP)

React SPA. Two-step flow:
1. Select plan (Free / Mail Plus / Unlimited / Family)
2. Create account form

```
Fields:
  input#username          text, the local part
  dropdown                @proton.me or @pm.me (2 domains)
  input#password          password
  button "Start using Proton Mail now"   submit
```

Only 2 fields visible. But after submit:

#### Post-Submit Verification

**This is where Proton fails.** After clicking submit, Proton presents a
risk-based challenge:

- **CAPTCHA** (hCaptcha) — always on free accounts
- **Email verification** — sometimes offered as alternative
- **Phone verification (SMS)** — triggered for VPN/Tor/datacenter IPs

Running from a TEE on Phala Cloud (datacenter IP) will almost certainly
trigger phone verification. This is a **hard blocker** for automated
account creation.

#### Protocol Support

| Protocol | Available? |
|----------|-----------|
| IMAP | Only via Proton Mail Bridge (paid plans, desktop app) |
| SMTP | Only via Proton Mail Bridge (paid plans, desktop app) |
| JMAP | No |
| API | No public API. Unofficial `go-proton-api` exists |

Bridge is a desktop application that must run alongside. Impractical inside
a container/TEE.

#### Recovery

Optional recovery email and phone. Can be skipped during signup.

#### Why NOT Proton

1. **Phone verification from datacenter IPs** — hard blocker
2. **No IMAP without Bridge** — can't read emails programmatically
3. **React SPA** — more complex to automate than plain HTML
4. **hCaptcha** — harder to solve than cock.li's CSS captcha
5. **2 domains only** — less opacity

---

### 3. Tuta (formerly Tutanota)

**Homepage**: https://tuta.com
**Registration**: https://app.tuta.com/signup

#### Signup Form (inspected live via CDP)

Custom SPA framework. Two-step flow:
1. Select plan (Free / Revolutionary / Legend)
2. Create account form

```
Fields:
  input[aria-label="Username"]          text, the local part
  dropdown                              @tutamail.com or @tuta.com
  input[aria-label="Set password"]      password
  input[aria-label="Repeat password"]   password confirmation
  checkbox                              "I do not own any other Free account..."
  checkbox                              "I have read and agree to..." ToS
  button "Create account"               submit
```

#### Post-Submit Flow

After submit, Tuta shows a "Recovery Kit" step (step 3) — a recovery code
you're asked to save. **Can be skipped/ignored**, making the account
irrecoverable. No CAPTCHA on the form itself.

However: accounts created from VPN/Tor/datacenter IPs may be **queued for
manual approval** (up to 48 hours).

#### Protocol Support

| Protocol | Available? |
|----------|-----------|
| IMAP | **No** |
| POP3 | **No** |
| SMTP | **No** |
| JMAP | **No** |
| API | **No public API** |

Tuta intentionally blocks all standard email protocols. Their E2E encryption
architecture requires their client. There is an unofficial `tuta2imap` bridge
but it's fragile and unmaintained.

#### Account Deletion Policy

**Free accounts are deleted after 6 months of inactivity.** This is stated
on the signup page. A TEE-held account would need periodic logins to stay alive.

#### Why NOT Tuta

1. **No IMAP/SMTP/API** — absolute blocker. Cannot read emails programmatically.
2. **6-month inactivity deletion** — requires keepalive mechanism
3. **Manual approval queue** from datacenter IPs — unpredictable wait
4. **2 domains only**
5. Custom SPA — harder to automate than plain HTML

---

### 4. Fastmail

**Homepage**: https://fastmail.com
**Registration**: https://app.fastmail.com/signup/

#### Signup Form (inspected live via CDP)

Overture framework SPA. Single-page form:

```
Fields:
  input#v21-input  name="name"           text, display name
  checkbox#v22-input                     "Use your own domain" toggle
  input#v23-input                        text, email username
  select#v26-input                       23 domain options
  input#v29-input  name="new-password"   password
  button#v32       "Start your free trial"  submit (initially disabled)
```

No CAPTCHA on the form.

#### Available Domains (23)

```
fastmail.com    fastmail.ca    fastmail.cn    fastmail.co.uk
fastmail.com.au fastmail.de    fastmail.es    fastmail.fm
fastmail.fr     fastmail.im    fastmail.in    fastmail.jp
fastmail.mx     fastmail.net   fastmail.nl    fastmail.org
fastmail.se     fastmail.uk    fastmail.us    fea.st
sent.com        pobox.com      123mail.org
```

#### Protocol Support — BEST

| Protocol | Available? |
|----------|-----------|
| IMAP | Yes |
| SMTP | Yes |
| JMAP | **Yes** — full RFC 8620/8621, scoped read-only API tokens |
| CardDAV/CalDAV | Yes |

Fastmail has the best programmatic email access of any provider evaluated.
Scoped API tokens with read-only permissions are ideal for pin extraction.

#### Post-Submit Flow

30-day free trial. After trial:
- IMAP disabled on unverified trial accounts
- JMAP API tokens not available on Basic plan
- SMS verification may be triggered (risk-based)

#### Recovery

Recovery email and phone can be added but also **removed after setup**.
Fastmail has a 24-hour recovery delay with email notification as a safety
measure. Recovery code always exists internally.

#### Payment

Required after 30-day trial. Accepts Visa/MC/Amex/PayPal/Apple Pay.
Prepaid cards often rejected (delayed capture issue).

#### Why NOT Fastmail (as primary)

1. **Requires payment** after 30 days — need virtual card inside TEE
2. **SPA framework** — more complex than plain HTML
3. **Trial limitations** — IMAP restricted, API tokens on paid plans only
4. **SMS verification risk** from datacenter IPs
5. **Name field required** — minor, easily faked

#### Why Fastmail COULD be secondary

Best JMAP API with scoped tokens. If payment is solved (virtual card
provisioned inside TEE), Fastmail is the superior long-term option for
programmatic email access. Consider as upgrade path after proving the
system works with cock.li.

---

## Comparison Matrix

| Criteria | cock.li | Proton | Tuta | Fastmail |
|----------|---------|--------|------|----------|
| **Free forever** | ✅ | ✅ | ⚠️ 6mo inactivity delete | ❌ 30-day trial |
| **No phone required** | ✅ Never | ❌ Often from datacenter | ✅ Never | ⚠️ Risk-based |
| **No existing email required** | ✅ | ✅ | ✅ | ✅ |
| **IMAP access** | ✅ | ❌ Bridge only (paid) | ❌ None | ✅ |
| **SMTP access** | ✅ | ❌ Bridge only (paid) | ❌ None | ✅ |
| **JMAP/API** | ❌ | ❌ | ❌ | ✅ Best-in-class |
| **No recovery mechanism** | ✅ None exists | ⚠️ Optional | ⚠️ Recovery kit | ⚠️ Can remove |
| **Signup form complexity** | Plain HTML POST | React SPA | Custom SPA | Overture SPA |
| **CAPTCHA type** | CSS pixel art (SOLVED) | hCaptcha | None | None |
| **Datacenter IP friendly** | ✅ | ❌ Phone triggered | ⚠️ Manual queue | ⚠️ SMS risk |
| **Domains available** | 15 | 2 | 2 | 23 |
| **TEE precedent** | ✅ TEE_HEE | ❌ | ❌ | ❌ |
| **CDP automation effort** | **Low** (captcha solved) | High | Medium | Medium |
| **Account persistence** | ✅ Indefinite | ✅ Indefinite | ❌ 6mo delete | ❌ Requires payment |

---

## Decision: cock.li

### Why cock.li wins

1. **Simplest automation target.** Plain HTML form with named fields. No SPA
   framework state management, no client-side routing, no hydration issues.
   A `browser-use` agent or raw Playwright script can complete signup in
   under 30 seconds.

2. **Captcha is fully solved.** CSS box-shadow pixel art parsed directly from
   HTML, template-matched at 100% accuracy with ~2ms latency. No LLM vision
   call needed. CPU-only, no external API dependencies.

3. **Standard IMAP.** `mail.cock.li:993` with TLS. Any IMAP library
   (Python `imaplib`, Node `imap-simple`) can connect, authenticate, and
   read emails. No proprietary bridges, no API tokens, no OAuth flows.

4. **No phone verification ever.** Even from datacenter IPs, VPNs, or Tor.
   The site explicitly states: "You will never be asked to verify personal
   information." This is critical for TEE deployment on Phala Cloud.

5. **No recovery mechanism.** There is no recovery email, phone, security
   question, or backup code system. Once the password is sealed inside the
   TEE, the account is permanently locked to that enclave. This is exactly
   the security property we need.

6. **Free forever.** No payment means no credit card inside the TEE, no
   trial expiration, no risk of account suspension for payment failure.

7. **Battle-tested for TEE account delegation.** TEE_HEE (Nous Research /
   Flashbots / Andrew Miller) used cock.li for exactly this purpose. The
   `cucumber-twitter2` repo demonstrates the browser-use pattern for
   automated account operations.

8. **Multiple presentable domains.** `firemail.cc` and `airmail.cc` are
   usable in professional contexts. 15 domains total provide opacity.

9. **Account persistence.** No inactivity deletion policy. The account
   persists indefinitely without requiring keepalive logins.

10. **Tor hidden service.** If needed, the TEE can access cock.li entirely
    over Tor for additional network-level privacy.

### What cock.li lacks (and why it doesn't matter)

- **No JMAP API** — We read emails via IMAP, which is universally supported
  and well-understood. JMAP would be nicer but IMAP is sufficient for
  extracting 6-digit pins from verification emails.

- **No scoped tokens** — Authentication is username+password over IMAP TLS.
  Since the credentials never leave the TEE, this is acceptable. The
  password IS the token.

- **No E2E encryption** — cock.li can read emails in transit/at rest. We
  accept this (same as Fastmail). Pins are short-lived and extracted within
  seconds. For higher assurance, swap to self-hosted Stalwart.

- **Unprofessional domain names** — Use `firemail.cc` or `airmail.cc`.
  The email address is never shown to humans anyway — it exists only as
  a verification target inside the TEE.

- **Single operator** — cock.li is run by a small team. If the service
  goes down, the email account is inaccessible. Mitigation: the TEE can
  monitor account health and alert. The credentials remain sealed
  regardless of service availability.

### Automation Stack

Based on `amiller/cucumber-twitter2`:

```
browser-use          LLM-driven CDP automation (Python)
  └─ playwright      headless Chromium via CDP
      └─ gemini/claude   LLM for form navigation (captcha solved locally)
```

**Signup automation steps (CDP)**:

```python
# 1. Navigate to registration
page.goto("https://cock.li/register.php")

# 2. Fill form fields (plain HTML, direct selectors)
page.fill('input[name="username"]', generated_username)
page.select_option('select[name="domain"]', 'firemail.cc')
page.fill('input[name="password"]', generated_password)
page.fill('input[name="password_confirm"]', generated_password)

# 3. Solve captcha (CPU-only, no LLM needed)
html = page.content()
from captcha_solver import solve_from_html
solution = solve_from_html(html)
page.fill('input[name="captcha_solution"]', solution)

# 4. Accept ToS
page.check('input[name="tos_agree"]')

# 5. Submit
page.click('button:text("Register")')

# 6. Seal credentials via dstack-KMS
seal_credentials(username, password, domain)
```

**Pin extraction (IMAP)**:

```python
import imaplib
import re

mail = imaplib.IMAP4_SSL('mail.cock.li', 993)
mail.login(username, password)
mail.select('INBOX')

# Search for recent emails from specific sender
_, ids = mail.search(None, f'FROM "{sender}" SINCE "{cutoff}"')
for msg_id in ids[0].split():
    _, data = mail.fetch(msg_id, '(BODY[TEXT])')
    body = data[0][1].decode()
    pin = re.search(r'\b\d{6}\b', body)
    if pin:
        return pin.group()
```

---

## Upgrade Path

If cock.li proves insufficient long-term (service reliability, deliverability
issues), the system is designed to be provider-agnostic:

1. **Fastmail** — swap IMAP for JMAP, add payment automation
2. **Migadu** — REST API for mailbox creation, standard IMAP, requires own domain
3. **Self-hosted Stalwart** — full JMAP+IMAP, zero third-party trust,
   eliminates T7 (provider reads emails) from threat model entirely

The credential store and pin extraction API remain identical regardless
of provider. Only the signup automation and email reading transport change.
