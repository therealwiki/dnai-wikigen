# Architecture Decisions

This ledger records architecture choices that affect trust boundaries,
deployment topology, funding rails, quote verification, data locality, and
frontend verification. Status labels match `ARCHITECTURE.md`:

- `[real]` implemented and locally verified.
- `[partial]` implemented but not production-complete.
- `[modeled]` specified or stubbed but not enforced end to end.
- `[planned]` target only.

## 2026-07-08: Result-Submission Quote Verification Path

Status: `[partial]`

Decision:

`DiligenceRoom.submitResult()` quote verification will proceed in two stages.

1. `[real]` The current submitter uses an off-chain verifier gate before
   broadcast. In dstack mode it derives the Ethereum signer inside the TEE,
   fetches quote evidence whose `report_data` binds the signer address, chain
   ID, and DiligenceRoom contract address, verifies the quote envelope fields,
   and only then signs and broadcasts `submitResult()`.
2. `[real]` `DiligenceRoom.sol` requires a configured result-verifier
   signature before accepting `submitResult()`. The authorization binds chain
   ID, contract address, deal ID, TEE identity, compose hash, score band,
   compute cost, replay-bound result commitment, and authorization expiry.
3. `[partial]` The bounded receipt records the signer attestation hash,
   normalized report data, quote size, compose hash, signer address, chain ID,
   contract address, signer nonce, replay-bound result commitment,
   authorization expiry, and verifier-signature hash. This is enough for local
   verifier tooling and reviewer audit, but not yet enough for production quote
   verification because the verifier service/policy is not built.
4. `[real]` `tinker_delegate.result_verifier` implements the policy/signature
   core for the production verifier path. It accepts bounded signer attestation
   evidence only when it matches signer address, chain ID, contract address,
   report data, quote report data, approved compose hash, approved app ID,
   optional OS image hash, revocation policy, distinct verifier/TEE keys, and a
   short authorization TTL; then it signs the exact contract digest.
5. `[real]` The operator CLI path wraps this module:
   `result-verifier-address` emits the dstack-derived verifier address, and
   `authorize-result` consumes bounded signer-attestation JSON plus explicit
   allowlists/revocations before returning authorization metadata and the public
   verifier signature needed by the contract.
6. `[planned]` A production verifier service must expose the same bounded
   authorization path in a deployed CVM and add cryptographic Intel TDX quote
   parsing/freshness before the repo can claim complete production quote
   verification.

Rationale:

- Full Intel TDX quote parsing is not exposed by the current local dstack SDK
  helpers, so the repo should not claim complete cryptographic quote
  verification in Python or Solidity.
- The pre-broadcast gate is still meaningful progress: a normal operator path
  cannot use the `submit-result` CLI without dstack mode, dstack-derived signer
  custody, and signer quote evidence that matches the intended chain and
  contract.
- `DiligenceRoom.sol` now has the verifier-signature hook, which intentionally
  breaks the previous deployed ABI. Fresh deployments must configure
  `DILIGENCE_RESULT_VERIFIER` or explicitly accept the deployer as the local
  smoke-test verifier.

Open follow-ups:

- `[real]` Add a verifier signature format for result submissions.
- `[real]` Add contract enforcement so a bogus bare `teeIdentity` cannot submit
  without a verifier authorization.
- `[real]` Add the bounded policy/signature core for the production verifier
  path.
- `[real]` Wrap the verifier module as a bounded operator CLI path.
- `[planned]` Deploy the verifier path as a service inside the Phala/CVM stack.
- `[planned]` Add full cryptographic quote parsing/freshness once production
  Phala quote evidence is available.
- `[planned]` Repeat the proof from a deployed Phala CVM, not only the local
  simulator.

## 2026-07-11: CVM Topology — Single Combined CVM

Status: `[partial]`

Decision:

Run the email-oracle and the tinker-delegate as one combined dstack CVM for
now, not two separately-attested CVMs. Live evidence (2026-07-11): app
`f6a3219…` / CVM `cvm_1w85mGjo` serves the oracle (port 8000), the delegate
(port 8080), and the Neko/Playwright browser sidecar (9222/52000) under a single
app id and one compose hash, reachable on the `dstack-pha-prod9.phala.network`
gateway.

Rationale:

- A single CVM lets the delegate reach the oracle's OTP path and the browser
  sidecar over the pod-internal network without cross-CVM RA-TLS, which is not
  built yet.
- The cost is a coarser trust boundary: oracle and delegate share one
  measurement, so a compromise of either is a compromise of both, and
  same-CVM derived-key bearer auth substitutes for attested cross-service auth.

Open follow-ups:

- `[planned]` Split into per-service CVMs with RA-TLS or attestation-backed
  signed requests once the combined flow is proven end to end (see
  `EmailOracleAuth Completion` split-CVM item in `TODO.md`).
- `[partial]` The current CVM still runs `dstack-dev` with `public_logs=true`
  and `os.is_dev=true` — a debugging posture, not production isolation.

## 2026-07-11: Funding Rails — Encumbrance-Gated Browser-Mediated Top-Up

Status: `[partial]`

Decision:

Tinker compute is funded by a developer prefund: card details are encrypted to
the TEE, entered through the CVM-held Neko browser session, and converted to a
Tinker balance. Every paid operation is gated on-chain by
`TinkerAccountEncumbrance` (approved compose hash, per-op add-balance cap, spend
cap, emergency halt) before any decryption or browser automation runs. Buyer
compute deposits and developer fees settle through `DiligenceRoom` escrow,
kept conceptually separate from the Tinker account top-up rail.

Rationale:

- Keeping card material encrypted-to-TEE and gating spend on a frozen on-chain
  policy means no human operator and no unapproved measurement can move money.
- Browser-mediated entry is a bridge until a first-class payment API path
  exists; it is why the Neko sidecar shares the CVM.

Open follow-ups:

- `[partial]` One-off low-value real funding is proven (bounded `$10.00`
  balance read); repeated/production funding, A2A/ACH/card automation, and
  connecting Tinker spend to buyer escrow + developer fee remain open
  (`Milestone 1` funding-rail items in `TODO.md`).
- `[planned]` Emit on-chain events for every funding operation
  (requested/authorized/attempted/succeeded/failed/card-destroyed).

## 2026-07-11: Data Locality — Sealed At Rest, Plaintext Only In Boundary

Status: `[partial]`

Decision:

Private data (reward datasets, artifacts, credentials) may be stored on
untrusted hosts only as ciphertext; plaintext exists only inside the attested
boundary. Datasets use envelope encryption (per-dataset DEK, chunked
AES-256-GCM, DEK wrapped to attestation-bound CVM keys) with a bounded,
owner-signable manifest; artifacts are encrypted to the TEE public key with
per-deal/per-artifact HKDF context and never touch disk unencrypted; OTP-replay
and API-key state persist only through sealed stores.

Rationale:

- This is what lets reward datasets live on Hugging Face / S3 / IPFS while the
  reward oracle stays private, and what lets the diligence room hold an artifact
  without a human seeing it.
- Storage backends are deliberately orthogonal to the crypto path, so adding a
  host never touches encryption.

Open follow-ups:

- `[partial]` The unwrap key is not yet bound to an approved CVM measurement via
  cryptographic TDX quote parsing, so the store stays `[partial]` and inherits
  the attestation + compose-approval chain (shared blocker with quote
  verification). Recipient custody today is a local key file, not dstack-derived.
- `[planned]` CVM-side fetch → sealed-volume write → buffer-zero wiring, and a
  neutral sealing witness for adversarial buyer/seller pairs.

## 2026-07-11: Frontend Deployment Target

Status: `[planned]`

Decision:

The demo UI (`gate-health-frontend`, a Vite/React app) lives on a separate
branch and is not yet integrated into the attested deployment. The verification
UX target is that the browser independently checks the live TDX quote, compose
hash, and report-data key binding before any artifact is encrypted and
uploaded — the client-side quote-verifier/uploader already exists in
`tinker_delegate` as a CLI, and the frontend is expected to reuse that same
bounded verification chain rather than trust the server.

Rationale:

- The trust story only holds if the buyer's own client verifies attestation;
  putting verification in the frontend (not the server) keeps the boundary
  honest.

Open follow-ups:

- `[planned]` Choose and wire the deployment target (static host vs. served from
  the CVM gateway), and port the client-side quote verification into the
  frontend so the demo proves attestation from the user's browser.
