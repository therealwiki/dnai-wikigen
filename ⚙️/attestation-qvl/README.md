# DNAI Independent Attestation QVL

Status: implemented and locally tested; no project-owned instance from the
fresh release has been deployed or independently activated.

This is a separate, least-privilege Intel TDX quote-verification service. In a
production release it must run in its own real Phala CVM, outside the evaluated
workload CVM. An authenticated workload first obtains a short-lived, signed,
policy/profile-scoped one-time challenge. It places the static release digest
in quote `report_data` bytes 0–31 and the challenge digest in bytes 32–63, then
sends that exact raw quote plus bounded public expectations to the QVL. The QVL
verifies the quote independently, atomically consumes the challenge, and
returns the bounded signed v4 verdict with its separate activation-evidence
lease.

This project does not deploy itself. `docker-compose.production.yml` is a reviewed, production-shaped handoff for a separate Phala deployment. Never add this service to the evaluated workload's compose project, Docker network, volume set, or CVM.

## Security result

`POST /challenge` and `POST /verify` implement the following protocol:

1. Authenticates the bearer token with constant-time comparison before capacity admission, body reads, parsing, challenge issuance, quote collection, or DCAP work.
2. Issues a cryptographically random nonzero 32-byte challenge ID, bound to the canonical release-policy hash and one enabled profile, with a maximum 120-second lifetime. The QVL signer EIP-191-signs the challenge digest.
3. Keeps challenges only in a bounded in-memory store. Reservation is atomic (`fresh → reserved → consumed`); success, rejection, cancellation, and timeout all consume the reservation. Replays and concurrent second users fail before DCAP work.
4. Caps each HTTP body at 96 KiB and each decoded quote at 16 KiB, pre-checks every streamed chunk before extending the buffer, and applies a body-read timeout.
5. Parses duplicate-free JSON into exact, strict Pydantic schemas with unknown fields and coercion forbidden; recursion failures map to a fixed error.
6. Recomputes the quote byte length and SHA-256 hash and treats every request expectation as an assertion, never as policy authority.
7. Loads chain ID, contract, compose hash, app ID, OS image hash, signer allowlist, enabled report-data profiles, exact TDX measurements, validity, and verdict TTL from a separately delivered release policy.
8. Independently derives the static 32-byte profile digest and requires the quote's exact 64-byte `report_data` to contain it in bytes 0–31 and the signed challenge digest in bytes 32–63.
9. Runs the official `dcap-qvl==0.5.2` Intel DCAP/PCCS verification under an application timeout. A timed-out challenge remains consumed.
10. Accepts only a TDX quote and the exact verified DCAP status string `OK`. The policy schema cannot authorize `REVOKED`, `OUT_OF_DATE`, `CONFIGURATION_NEEDED`, hardening-needed states, mixed sets, or arbitrary future strings.
11. Requires an exact match for every policy-pinned TDX measurement and rejects the TDX DEBUG bit.
12. Re-reads the clock after DCAP and measurement validation, rejects completion at or after either the challenge or policy expiry (and clock rollback), then bases the verdict issue time and TTL on that completion time.
13. Reconstructs all verdict labels from policy-owned values, binds the full release/CVM lineage, profile, policy hash, challenge ID/digest/times, quote, workload context, and activation-evidence lease into schema `dnai.independent-tdx-verdict.v4` under domain `dnai-wikigen/independent-tdx-verdict/v4\0`, and EIP-191-signs that digest.

The challenge and activation-evidence lease are deliberately different clocks.
Every challenge is single-use and valid for at most 120 seconds, and DCAP
appraisal must finish strictly before it expires. The reviewed release policy
then requires an exact 900-second activation-evidence lease beginning at the
successful appraisal time. That lease may outlive the already consumed
challenge; it is policy-bounded authority to consume the appraisal, not renewed
challenge freshness.

The only accepted collateral origin is the compiled release endpoint `https://pccs.phala.network`. Startup rejects alternate domains, IP literals, loopback, credentials, ports, paths, query strings, fragments, and even a trailing slash.

The service contains no quote logging or persistence path. Uvicorn access logs, OpenAPI, Swagger UI, ReDoc, proxy-header trust, and server-version headers are disabled. `POST /verify` never echoes the evaluated workload quote. The authenticated `POST /attestation` route is the deliberate exception: it returns the QVL CVM's own raw quote so an external activation verifier can validate the QVL root. Bearer tokens, collateral, PPIDs, advisory lists, request assertions, dstack key responses, and signing keys are never included in responses. Parser, filesystem, DCAP, policy, and signer failures map to fixed no-detail error codes.

## Report-data profiles

One release policy selects exactly one primary discriminated `report_data_binding`. That primary binding enables exactly one workload profile. A Diligence policy may additionally include the exact optional `royalty_settlement_binding` and `email_oracle_kms_restart_binding`. Only then may that same measured Diligence QVL CVM and challenge store issue the corresponding secondary `royalty_settlement` or `email_oracle_kms_restart` profile. Royalty uses its own dstack key and EIP-712 domain; it does not reuse the Diligence verdict/result signer. Request input can select only a profile already enabled by the reviewed policy.

### Diligence result signer

`{"kind":"diligence_result_signer_v1"}` computes SHA-256 over sorted, compact JSON:

```json
{"chain_id":84532,"context":"diligence-room-submit-result","contract_address":"0x...","service":"dnai-wikigen","signer_address":"0x..."}
```

The signer and contract addresses are lowercase policy values. This is byte-for-byte compatible with `tinker_delegate.chain_submitter.signer_attestation_report_data`.

### Royalty settlement on the existing Diligence QVL

`royalty_settlement_qvl_v2` is an optional secondary policy on the existing
Diligence QVL CVM. It does **not** add an eighth CVM. The Diligence QVL is the
independent party that appraises a fresh main-runtime Collaboration/Compute
release quote; a separate purpose-derived QVL key then co-signs one exact
reserved `RoyaltyDistributor` v3 settlement.

The binding is Base-Sepolia-only and pins:

- the `RoyaltyDistributor` governance owner, contract address, and runtime-code hash;
- the sole main-runtime settlement verifier, literal key path, and dstack custody label;
- the `ExecutionPolicyAnchor` address and frozen writer-release commitment;
- the active Royalty release-policy commitment and nonzero authority nonce;
- a nonzero Royalty-QVL key ID;
- the exact main-runtime CVM ID, deployment-intent digest, release-authority digest, and measurement-policy digest; and
- the literal maximum authorization lifetime of 600 seconds.

The policy is accepted only on a Diligence primary binding with exactly one
main-runtime signer. The Diligence contract, distributor, main-runtime signer,
and anchor must all be nonzero and pairwise distinct. At QVL construction the
service derives the Royalty signer and byte-for-byte recomputes the contract's
`RoyaltyReleasePolicy` commitment from chain ID, distributor, authority nonce,
main settlement verifier, derived QVL verifier, anchor, and anchor-writer
release. A mismatch prevents startup.

The owner, Diligence contract, distributor, main settlement signer, independent
QVL signer, and execution-policy anchor are required to remain distinct. The
main runtime's static quote digest uses domain
`dnai-wikigen/royalty-settlement-signer-attestation/v1\0`. It commits the exact
main-CVM lineage and measurements, distributor/runtime pin, main settlement
signer path/custody, active release commitment, derived Royalty verifier, and
canonical Royalty policy commitment. The challenge digest remains in quote
`report_data` bytes 32–63, so an old quote cannot be reused for a new request.

The exact nested request schema is
`dnai.royalty-settlement-qvl-authorization-request.v2`. It covers every field
of the contract's `RoyaltySettlementQvlAuthorization` type:

```text
settlement_id, settlement_nonce, funding_reservation_id,
release_policy_commitment,
room_commitment, room_state_commitment, query_commitment,
grant_set_commitment, allocation_commitment, owners_amounts_hash,
asset, total, execution_commitment, result_commitment, usage_commitment,
attestation_evidence_hash, anchor_resource_hash, anchor_decision_hash,
anchor_sequence, expiry
```

`funding_reservation_id` is required and nonzero, so this production QVL path
authorizes only a contract-backed funding reservation; omitted, zero, aliased,
extra-field, and legacy-v1 packets fail schema validation. The v2 Royalty QVL
policy commitment explicitly pins this request-schema version. The object also
carries the main runtime's raw `RoyaltySettlementAuthorization` digest
and signature. After independent DCAP appraisal, the QVL recomputes the fresh
quote-evidence hash, active release commitment, collaboration resource hash,
settlement decision hash, and main-runtime EIP-712 digest. It requires a
canonical low-s signature from the policy-pinned main-runtime settlement
verifier. Therefore changing any settlement, evidence, anchor, or policy field
without a new measured-main-runtime signature fails. The contract remains the
final live-head authority: at broadcast it independently requires the resource
head, decision head, and both sequences to match its configured anchor, so an
anchor change after QVL appraisal cannot settle.

Only then does the QVL reproduce the contract's exact EIP-712 domain
(`DNAI Royalty Distributor`, version `3`, Base Sepolia chain ID, exact
distributor) and `RoyaltySettlementQvlAuthorization` type hash. It raw-signs
that digest using:

```text
dnai-wikigen/attestation-qvl/royalty-settlement-signer/v1/<qvl-signer-key-id>
```

The 65-byte signature has no EIP-191 prefix. The distinct dstack path,
`RoyaltySettlementQvlAuthorization` type, and the contract's EIP-712 version-3 domain
prevent replay as a Diligence result signature, generic verdict signature,
main-runtime settlement signature, or Compute metering receipt. The reservation
ID is bound in the settlement-decision hash, main-runtime authorization digest,
QVL authorization digest, and bounded anchor-evidence commitment. Expiry must be
strictly future, no more than 600 seconds after appraisal, and no later than
the one-time challenge or verdict-evidence lease.

The v4 verdict returns no settlement fields, main-runtime signature, or raw
quote. Its optional Royalty group is limited to the derived QVL address,
canonical Royalty policy commitment, active contract release commitment,
quote-evidence hash, anchor-evidence commitment, expiry, exact EIP-712 digest,
and raw signature. The ordinary verdict signer separately EIP-191-signs that
bounded envelope.

### Email oracle / KMS restart evidence on the Diligence root

The optional `email_oracle_kms_restart_v1` secondary binding is available only on a Base Sepolia Diligence policy with exactly one allowlisted main-CVM signer. It does not create a sixth QVL root or eighth CVM. The binding commits all of the following reviewed public evidence:

- `EmailOracleAuth` address and runtime-code hash;
- KMS proxy address and runtime-code hash;
- KMS implementation address and runtime-code hash;
- the complete EIP-1967 implementation storage word, required to be the implementation address left-padded with 12 zero bytes;
- registration transaction hash, block number, and block hash;
- target boot-tuple hash and restart-proof hash.

The static digest uses the dedicated domain `dnai-wikigen/email-oracle-kms-restart-attestation/v1\0` and canonical JSON containing schema, the policy-pinned Base Sepolia chain ID, the one policy-pinned main-CVM signer, and every field above. The signed QVL challenge and v4 verdict additionally bind the `email_oracle_kms_restart` profile, so a Diligence result quote and a restart/KMS quote cannot cross-authorize each other.

### Arena candidate ingress

`arena_candidate_ingress_v1` pins an exact 32-byte X25519 public key as 64 lowercase hex characters and its canonical key ID, `sha256:<sha256(public-key-bytes)>`. It computes SHA-256 over sorted, compact JSON:

```json
{"context":"arena","encryption_public_key":"...64 lowercase hex...","key_id":"sha256:...","protocol":"arena_candidate_ingress_v1","service":"dnai-wikigen"}
```

This is byte-for-byte compatible with `tinker_delegate.arena_ingress.arena_attestation_report_data`. The Arena digest intentionally binds the ingress key rather than the result signer. The signer allowlist, chain, contract, and all release labels are still independently matched against policy and included in the signed verdict.

### Execution-policy anchor writer

`execution_policy_anchor_writer_v1` pins the exact nonzero writer-release
commitment and accepts only the literal purpose-separated key path and custody
labels:

```json
{
  "kind": "execution_policy_anchor_writer_v1",
  "writer_release_commitment": "0x...32 bytes...",
  "writer_key_path": "tinker/execution_policy_anchor_writer",
  "writer_custody": "dstack_derived_execution_policy_anchor_writer"
}
```

It computes SHA-256 over the domain
`dnai-wikigen/execution-policy-anchor-writer-evidence/v1\0` followed by sorted,
compact JSON containing the evidence schema, Base Sepolia chain ID, anchor
address, writer address, writer release commitment, exact key path, and exact
custody label. The policy separately pins the writer CVM's app, compose, OS,
and complete TDX measurement map. A request cannot substitute any of those
values.

### Compute workload recipient

`compute_workload_recipient_v1` is the purpose-separated policy for the main
Compute CVM's dynamic X25519 recipient and activation signer. The QVL policy
pins the main CVM's compose hash, 40-character bare lowercase Phala app ID,
64-character bare lowercase OS image hash, and complete TDX measurements. It
requires an empty static signer allowlist because the recipient key and signer
are dstack-derived after deployment. Each verification request instead carries
the exact `dnai.compute-workload-recipient-attestation.v1` public recipient,
key ID, activation signer, Base Sepolia vault, runtime-code hash, and fresh
deployment-receipt commitment. The QVL independently rederives the report-data
digest and returns no private workload data.

### Compute metering signer

`compute_metering_signer_v1` is a purpose-separated policy profile for
the independent compute-metering CVM. The release policy's top-level
`chain_id` must be Base Sepolia (`84532`), `contract_address` is the exact
nonzero `ComputeCreditVault`, and `allowed_signer_addresses` must contain
exactly one derived metering verifier. The binding pins:

```json
{
  "kind": "compute_metering_signer_v1",
  "policy_set_hash": "0x...32 nonzero bytes...",
  "signer_custody": "dstack_derived_independent_cvm"
}
```

It computes SHA-256 over the domain
`dnai-wikigen/compute-metering-signer-attestation/v1\0` followed by ASCII,
key-sorted, compact JSON:

```json
{
  "schema": "dnai.compute-metering-signer-attestation.v1",
  "chain_id": 84532,
  "vault_address": "0x...",
  "metering_verifier": "0x...",
  "policy_set_hash": "0x...",
  "signer_custody": "dstack_derived_independent_cvm"
}
```

The QVL derives this independently from its reviewed policy plus the one
allowlisted signer. It does not trust the policy-set hash or custody label from
the metering endpoint. The derivation is byte-for-byte compatible with
`compute_metering.identity_attestation.metering_identity_report_data`.

For a metering decision, the same `POST /verify` request may carry exactly one
`compute_authorization` object with the complete
`dnai.compute-metering-qvl-authorization-request.v1` field set. The QVL first
verifies and consumes its own fresh compute-profile challenge and independently
validates the TDX quote, measurements, release policy, static report-data
binding, and quote-evidence hash. It then requires the exact policy-set and
compose roots, coherent nonzero billable units, debit no greater than the job
cap, usage end not before start, and a receipt expiry no later than the job,
challenge, verdict, or ten-minute freshness ceiling.

Only after those checks does the QVL construct the
`ComputeMeteringQvlReceipt` EIP-712 digest using the vault's exact v2 domain and
the submitted project/job/user/asset/nonce/cap/debit/expiry, rate policy,
workload, manifest, dispatch intent, execution TEE, compose, start commitment,
billable units, usage interval, vault-derived usage commitment, metering policy
set, and quote-evidence hash. It signs that digest **raw**, without an EIP-191
prefix, using the QVL's purpose-separated dstack key. The returned bounded v4
verdict still has its separate EIP-191 verdict signature; the two signatures
serve different consumers and are not interchangeable. `ComputeCreditVault`
requires this raw QVL signature together with the distinct meter's raw
`ComputeMeteringReceipt` signature.

Deploy separate policy/service instances for Diligence, Arena, the anchor
writer, Compute workload, and compute metering. Their different policy hashes
produce different verdict-signing key paths and therefore distinct verifier
roots even if every other release field is identical. The optional Royalty and
email/KMS restart profiles intentionally share the Diligence policy, challenge
store, and CVM. Royalty alone derives an additional purpose-specific raw signer
inside that existing Diligence CVM.

## HTTP surface

- `GET /health` returns liveness only: `{"status":"ok"}`.
- `GET /identity` returns the bounded verifier address, canonical release-policy hash, dstack custody label, and `raw_secret_egress:false`.
- `GET /capabilities` returns `dnai.attestation-qvl-capabilities.v1`. It always says whether the optional Royalty protocol is configured and includes the accepted v2 authorization schema, secondary verifier address, and canonical Royalty policy commitment only when it is. This is discovery data, not independent attestation evidence.
- `POST /challenge` is authenticated and issues one signed, short-lived, policy/profile-scoped challenge from the bounded one-time store.
- `POST /verify` is authenticated, reserves exactly the supplied QVL-issued challenge, performs strict independent quote verification, requires appraisal to finish strictly before the at-most-120-second challenge expires, consumes the challenge on every terminal path, and returns only the bounded `dnai.independent-tdx-verdict.v4` verdict with its policy-bounded activation-evidence lease. It never returns a raw quote.
- `POST /attestation` is authenticated and mandatory in the production runtime. It accepts an externally generated activation-verifier challenge; the QVL does not self-issue this challenge. It returns the QVL CVM's own fresh raw quote with the static QVL identity digest in bytes 0–31 and the external challenge digest in bytes 32–63.

`POST /attestation` validates the external challenge's exact schema, digest, and lifetime, but intentionally does **not** maintain the activation verifier's replay ledger. The external verifier must generate unpredictable challenges, consume each challenge once before accepting any outcome, and reject reused responses. The repository activation preflight owns that bounded external ledger and independently performs Intel TDX DCAP verification.

The challenge request is exactly:

```json
{
  "schema": "dnai.attestation-qvl-challenge-request.v2",
  "chain_id": 84532,
  "domain": "main_runtime_cvm",
  "profile": "diligence",
  "cvm_id": "cvm-main-runtime-0001",
  "deployment_intent_sha256": "sha256:...",
  "release_authority_sha256": "sha256:...",
  "ceremony_nonce": "0x...32 bytes...",
  "measurement_policy_sha256": "sha256:..."
}
```

The response is `dnai.attestation-qvl-challenge.v2`. It echoes that exact
lineage tuple and adds `release_policy_hash`, random `challenge_id`,
deterministic `challenge_digest`, `issued_at`, `expires_at`,
`verifier_address`, and `verifier_signature`. Consumers must authenticate the
signature and match every lineage, profile, policy, lifetime, and verifier
field against external release authority before requesting a quote.

The exact verification envelope accepted from Diligence, Royalty, Arena, anchor-writer, and compute-metering clients is:

```json
{
  "schema": "dnai.independent-tdx-verification-request.v2",
  "challenge": {
    "schema": "dnai.attestation-qvl-challenge.v2",
    "chain_id": 84532,
    "domain": "main_runtime_cvm",
    "profile": "diligence",
    "cvm_id": "cvm-main-runtime-0001",
    "deployment_intent_sha256": "sha256:...",
    "release_authority_sha256": "sha256:...",
    "ceremony_nonce": "0x...32 bytes...",
    "measurement_policy_sha256": "sha256:...",
    "release_policy_hash": "0x...32 bytes...",
    "challenge_id": "0x...32 random bytes...",
    "challenge_digest": "0x...32 bytes...",
    "issued_at": 1800000000,
    "expires_at": 1800000060,
    "verifier_address": "0x...",
    "verifier_signature": "0x...65 bytes..."
  },
  "quote": "0x...raw quote hex...",
  "expectation": {
    "mode": "tdx",
    "signer_address": "0x...",
    "chain_id": 84532,
    "contract_address": "0x...",
    "report_data": "0x...32 bytes...",
    "quote_report_data": "0x...64 bytes: static digest || challenge digest...",
    "quote_hash": "0x...sha256...",
    "quote_size": 4096,
    "compose_hash": "0x...",
    "app_id": "...40 lowercase hex characters...",
    "os_image_hash": "...64 lowercase hex characters...",
    "raw_secret_egress": false
  }
}
```

Missing or additional keys, wrong JSON types, uppercase or noncanonical hex, duplicate object keys, mismatched labels, odd hex, and malformed quotes fail closed.

For Royalty, that envelope uses profile `royalty_settlement`, the policy-pinned
main-runtime CVM lineage, the distributor as `expectation.contract_address`,
and adds exactly one `royalty_authorization` object with schema
`dnai.royalty-settlement-qvl-authorization-request.v2`. Authorization domains
are mutually exclusive: a request cannot combine Royalty with Diligence result,
Compute metering, or Compute workload-recipient authority.

The activation request to `POST /attestation` is exactly
`dnai.qvl-identity-attestation-request.v3`. It binds the QVL CVM's own
`chain_id`, QVL `domain`, `profile`, canonical `cvm_id`, deployment intent,
release authority, ceremony nonce, measurement-policy digest, Phala app ID,
compose hash, OS image hash, and an externally chosen nonzero random challenge
ID into the activation-domain digest. Its lifetime may not exceed 120 seconds.
The response is `dnai.qvl-identity-attestation-response.v3`, echoes that exact
tuple, and binds the verifier address and QVL release-policy hash into report
data. Only an independently DCAP-verified, challenge-bound response establishes
a fresh real-TDX QVL identity; `/identity`, environment checks, local parsing,
or an unverified raw quote do not.

## External release policy

Use `release-policy.example.json` for Diligence and its optional same-root
Royalty and email/KMS restart profiles,
`release-policy.arena.example.json` for Arena, or
`release-policy.anchor-writer.example.json` for the purpose-separated anchor
writer. Use `release-policy.compute-metering.example.json` for the
purpose-separated metering signer and
`release-policy.compute-workload.example.json` for the dynamic Compute
recipient. These are shapes only. Even syntactically valid repeated-hex app and
OS values are placeholders. Every address, label, validity window, measurement,
release commitment, policy-set hash, key ID, and key must be replaced by independently
reviewed evidence.
Placeholder measurements must never authorize production.

The QVL process reads an external file at `/run/qvl/release-policy.json`. Its loader requires an absolute path, a regular non-symlink file, no group/world write bits, a maximum size of 64 KiB, stable inode/device/size/timestamps across the bounded read, duplicate-free JSON, and the exact schema.

Phala does not provide the deployer's local host path inside a remote CVM. The production compose therefore uses this concrete delivery flow:

1. The deployer validates and reviews one public policy JSON document.
2. The document is base64-encoded and supplied as `QVL_RELEASE_POLICY_B64` through Phala Encrypted Environment Variables. Base64 is only transport encoding; Phala's encrypted-variable channel supplies the protected deployment delivery.
3. A network-disabled, capability-free one-shot `policy-init` container validates the bounded, duplicate-free input, canonicalizes the policy, and atomically writes mode `0444` into a compose-scoped Docker volume.
4. The initializer exits. The QVL container receives no policy environment variable and mounts that volume read-only.
5. The only host bind in the QVL container is `/var/run/dstack.sock`, also read-only.

The image defaults to UID/GID 65532. The one-shot initializer explicitly uses UID 0 only because a fresh Docker-managed volume is root-owned; it has no Linux capabilities, no network, a read-only root filesystem, and write access only to the policy volume. The long-running QVL remains non-root and cannot modify the policy mount.

To inspect a local policy hash before deployment, first keep the file non-writable by group or world and use:

```bash
uv run python -c 'from pathlib import Path; import sys; from attestation_qvl.policy import load_release_policy; print(load_release_policy(str(Path(sys.argv[1]).resolve())).policy_hash)' /absolute/path/release-policy.json
```

To produce the strict one-line transport value without platform-specific `base64` flags:

```bash
uv run python -c 'import base64,sys; print(base64.b64encode(open(sys.argv[1], "rb").read()).decode("ascii"))' /absolute/path/release-policy.json
```

Provide that value and `QVL_AUTH_TOKEN` through the Phala dashboard's Encrypted Secrets section or the official CLI encrypted-environment workflow. Do not put either value directly in the compose file or commit a deployment `.env` file.

The canonical policy hash is SHA-256 over the validated policy serialized with sorted keys and compact separators, including defaults. The verdict key path is:

```text
dnai-wikigen/attestation-qvl/verdict-signer/v1/<canonical-policy-sha256>
```

When the Diligence policy enables Royalty, the service also derives:

```text
dnai-wikigen/attestation-qvl/royalty-settlement-signer/v1/<qvl-signer-key-id>
```

The reviewed active `release_policy_commitment` must be generated with that
derived address as the contract's QVL verifier. The example repeated-hex value
is only a schema placeholder; production startup deliberately fails if the
commitment does not recompute exactly.

Changing any policy field rotates the dstack-derived verifier address. Production has no raw-private-key environment variable, key file, mnemonic, fallback signer, or switch that disables QVL identity attestation. Test-only in-memory signers exist only behind the internal test dependency boundary.

## Verifier-root rollout

The `/identity` and `/capabilities` responses are discovery data, not trust roots by themselves. Before trusting a deployment:

1. Verify the reviewed policy and its canonical hash locally.
2. Verify the QVL CVM's platform/release evidence through Phala's attestation flow.
3. Generate a fresh external activation challenge, call authenticated `POST /attestation`, independently verify its raw TDX quote and DCAP collateral, and require both the static verifier/policy digest and the exact external challenge digest in the two report-data halves.
4. If Royalty is enabled, require the externally reviewed policy to contain the exact secondary binding, match the `/capabilities` address and policy commitment, and require the active Royalty release commitment to recompute with that secondary address.
5. Add the resulting primary verifier address to the delegate's externally reviewed trusted-verifier allowlist and configure the Royalty contract only with the separately verified secondary address.
6. Only then route evaluated-CVM quote requests to that deployment.

A policy update is a verifier-root rotation. Deploy a new isolated instance,
verify and approve the new root, update consumers, drain the old instance, and
then revoke the old root. Do not mutate one live service between Diligence,
Arena, anchor-writer, and compute-metering policies. A Royalty key-ID change is
also an explicit Royalty verifier rotation and requires a new active contract
release commitment.

## Production CVM and HTTPS boundary

The public compose substitutions are the immutable image reference:

```text
QVL_IMAGE_REPOSITORY=registry.example/dnai-attestation-qvl
QVL_IMAGE_DIGEST=sha256:...
```

The deployment's encrypted environment supplies:

```text
QVL_RELEASE_POLICY_B64=<strict base64 of reviewed public policy JSON>
QVL_AUTH_TOKEN=<random printable token, 32 to 4096 characters>
QVL_REQUEST_BODY_TIMEOUT_SECONDS=5
QVL_VERIFICATION_TIMEOUT_SECONDS=20
```

The request-body and DCAP-verification phases are sequential and their
configured timeouts must total at most 25 seconds. The production defaults use
the full 25-second server phase budget, leaving five seconds of headroom inside
each QVL consumer's 30-second end-to-end request timeout.

`docker-compose.production.yml`:

- uses the same digest-pinned application image for the initializer and QVL;
- runs the long-lived service as numeric UID/GID 65532;
- uses read-only root filesystems, no Linux capabilities, no privilege escalation, PID caps, and a small no-exec QVL tmpfs;
- uses a compose-scoped policy volume that is writable only by the exited initializer and read-only in the QVL;
- mounts only the QVL CVM's own dstack socket from the host;
- has no evaluated-CVM filesystem, socket, volume, service, or Docker network;
- publishes `8443:8443`, which Phala's gateway exposes as an HTTPS endpoint such as `https://<app-id>-8443.<gateway-domain>`;
- runs one Uvicorn worker so the process-global concurrency cap and token bucket remain global.

Configure the Diligence delegate, Royalty settlement producer, Arena worker,
one-shot anchor-writer bootstrap, or metering evidence collector with that context's exact HTTPS
`/verify` URL. The metering collector maps the authenticated
`dnai.compute-metering-identity-attestation.v2` packet to the generic request:
`metering_verifier` becomes `signer_address`, and `vault_address` becomes
`contract_address`; all quote and release labels are copied exactly. The
in-memory raw quote appears only in that authenticated request, while durable
release evidence should retain the bounded signed verdict. Do not connect an
evaluated CVM to the QVL compose network. At the deployment/network boundary,
restrict QVL egress to `pccs.phala.network:443` plus the DNS and platform
services required by Phala. The application-level PCCS pin prevents endpoint
substitution but is not a host firewall.

The production constructors explicitly reject the two simulator variables documented by the supported SDKs: `DSTACK_SIMULATOR_ENDPOINT` and `TAPPD_SIMULATOR_ENDPOINT`. They also require reachable dstack custody and quote APIs. This environment check is a fail-closed guard for those documented variables, not a claim that arbitrary undeclared simulator mechanisms can be identified from environment names. A real-TDX claim still requires external DCAP verification of the fresh challenge-bound quote.

## Development and verification

Use `uv`; never install this project with `pip`:

```bash
uv sync --frozen
uv lock --check
uv run --frozen python -m pytest
uv run python -m compileall -q src tests
IMAGE_TAG=dnai-attestation-qvl:test ./scripts/build-reproducible.sh
```

The build wrapper always passes `SOURCE_DATE_EPOCH=1735689600` explicitly. BuildKit's reproducible-image exporter requires an explicitly supplied nonzero epoch; relying only on a Dockerfile `ARG` default leaves the image-config creation time variable. The builder also removes uv's volatile local cache record, reconstructs the installed virtual environment in deterministic path order with normalized ownership/timestamps, and copies it to the runtime image at `/.venv`. Two independent `--no-cache` builds with that argument must produce the same image ID before publishing.

Tests use a fake quote backend and never download collateral or claim synthetic data is Intel evidence. Adapter tests pin the installed `dcap-qvl` version and its actual Python surface, including `VerifiedReport.status`, `Quote.is_tdx()`, `Quote.quote_type()`, TDX 1.0 fields, and optional TDX 1.5 fields. Royalty tests compare the request-v2/EIP-712-domain-v3 digest against the checked-in Solidity type strings, the real Tinker calldata encoder, an independent `eth-account` typed-data encoder, and a fixed KAT; mutate every signed contract field; reject legacy type hashes, substituted reservations, cross-profile authority, and EIP-191 replay; exercise policy/release/anchor/evidence/expiry drift; and enforce the authenticated body cap. Cross-project tests import the real delegate and compute-metering code, round-trip the HTTPS clients and metering quote packet through the FastAPI service, compare every purpose-specific report-data algorithm, compare the exact verdict digest, recover the EIP-191 signature, and authenticate the returned verdict using the delegate consumer.

## Deliberate remaining boundaries

This service is not a complete replacement for independent KMS governance, release provenance, reproducible-image review, DNS/network policy, gateway certificate validation, consumer root rotation, or on-chain governance monitoring. Those controls remain deployment and governance responsibilities. A QVL verdict proves only the policy-pinned quote and bounded context it signs.

## Primary references

- [Phala Network dcap-qvl source and Python bindings](https://github.com/Phala-Network/dcap-qvl)
- [Phala Trust Center technical architecture](https://docs.phala.com/dstack/trust-center-technical)
- [Phala Trust Center source](https://github.com/Phala-Network/trust-center)
- [Phala platform attestation verification](https://docs.phala.com/phala-cloud/attestation/verify-the-platform)
- [Phala encrypted environment variables](https://docs.phala.com/phala-cloud/cvm/set-secure-environment-variables)
- [Phala Docker Compose CVM deployment](https://docs.phala.com/phala-cloud/cvm/create-with-docker-compose)
- [Phala HTTPS gateway quickstart](https://docs.phala.com/phala-cloud/networking/quickstart)

These primary sources describe the DCAP trust chain, TCB validation, OS/application measurements, Trust Center separation, protected environment delivery, compose deployment, and HTTPS gateway surface used by this design.
