# Sealed Compute workload ingress

Status: implemented and locally verified, but production activation remains
blocked until an authenticated independent-QVL provider is configured for the
exact deployed CVM recipient. Provider dispatch remains separately disabled.

This boundary lets a wallet-authenticated user or a purpose-scoped device send
an inference prompt or canonical SFT JSONL workload to the verified Compute
CVM without first sending the plaintext to an ordinary API endpoint. There is
no raw prompt, examples, dataset, or model-output route.

## Public browser flow

1. `GET /compute/workload-encryption-contract` with `Cache-Control: no-store`.
2. Strictly parse the exact recipient, framing rules, size/count classes, and
   full signed `dnai.independent-tdx-verdict.v4` descriptor inside the exact
   `dnai.compute.workload-recipient-activation.v3` envelope.
3. Authenticate the verdict signature against a release-pinned independent QVL
   verifier and independently supplied Base Sepolia chain, QVL domain/profile,
   CVM ID, deployment intent, release authority, ceremony nonce, measurement
   policy, release policy, compose hash, app ID, OS image hash, execution
   signer, and contract. The measurement-policy-set and main-runtime-evidence
   digests must come from persisted release authority, never from the QVL
   response being authenticated.
4. Recompute the X25519 recipient key ID, the `compute_workload` report-data
   binding, v4 verdict digest, full v3 activation commitment, and stable
   `dnai.compute.workload-recipient-release.v2` commitment. Reject a stale,
   revoked, mismatched, local, simulator, unsigned, or self-asserted recipient.
5. Locally canonicalize the private inference or SFT payload, generate a fresh
   32-byte secret blind and random class padding with the browser CSPRNG, and
   build the sealed frame.
6. Derive the public commitments and canonical AAD, then encrypt with ephemeral
   X25519, HKDF-SHA-256, and AES-256-GCM.
7. Zero mutable copies of the payload, blind, padded plaintext, shared secret,
   nonce, and ciphertext after the ciphertext-only request has been prepared.
8. `POST /compute/projects/{project_id}/workloads` using a Compute wallet
   session or device credential with `workloads:create`, plus the same
   `Idempotency-Key` bound into the AAD.
9. Retain an unresolved prepared ciphertext request only in memory. An
   uncertain network retry must reuse byte-identical ciphertext and the same
   idempotency key; rebuilding with a new blind would correctly conflict.
10. Parse the ciphertext-free receipt and pass only `workload_id`,
    `workload_schema`, `manifest_commitment`, and `workload_commitment` into the
    exact-asset dispatch intent.

The SolidJS/browser implementation is frozen in
`web/src/lib/computeWorkload.ts`. The shared Python/TypeScript canonicalization
fixture is `web/src/lib/computeWorkloadWireVectors.json` and is marked as a
non-secret test vector.

## Private frame and leakage classes

The encrypted plaintext is exactly:

```
8-byte magic || 4-byte big-endian private length || 32-byte blind
|| private canonical payload || CSPRNG padding to the selected class
```

Payload classes are exactly 4,096, 16,384, 65,536, 262,144, and 1,048,560
plaintext bytes. AES-GCM adds a 16-byte tag, so the maximum ciphertext is
1,048,576 bytes. The largest private payload is 1,048,516 bytes after the
44-byte private header. Training example-count classes are `1_8`, `9_32`, `33_128`,
and `129_256`; inference uses `none`. Public metadata reveals the selected
classes, recipe, model, and resource caps, never the exact private byte length
or example count.

The workload commitment is:

```
SHA-256(
  "dnai-wikigen/compute-workload/v1\0"
  || canonical_manifest
  || 0x00
  || secret_blind
  || 0x00
  || private_payload
)
```

Because the blind is inside the encrypted frame, a public commitment cannot be
used as a confirmation oracle for a guessed prompt or small example set.

## Exact AAD binding

Canonical ASCII JSON AAD binds:

- service, context, and schema version;
- project commitment and authenticated actor kind/commitment;
- full public manifest and its commitment;
- secret-blinded workload commitment;
- project/actor/idempotency-key commitment;
- recipient key ID and report-data hash;
- the immutable upload-time authenticated activation commitment; and
- the stable authenticated recipient-release commitment used by the fresh
  execution-time QVL recheck.

The manifest binds the exact supported inference or SFT schema, `qwen3_8b`
model, one compiled recipe, privacy classes, and resource caps. Reusing a nonce
tuple, changing an AAD field, or reusing an idempotency key with a changed
request fails closed.

## Recipient activation boundary

`ComputeWorkloadRecipientActivation` has no public initializer. It can only be
created through `authenticate_compute_workload_recipient_activation`, which
calls the shared independent-attestation authenticator with expectations that
must originate outside the verdict. A boolean such as `verified=true` cannot
activate ingress. The full signed verdict is returned to the browser so the
browser can independently authenticate the same evidence before encryption.

The QVL uses a single-use signed challenge-v2 with a lifetime of at most 120
seconds. Intel DCAP appraisal must complete strictly before that challenge
expires. The active verdict is schema `dnai.independent-tdx-verdict.v4` under
signing domain `dnai-wikigen/independent-tdx-verdict/v4\0`; it carries the
separately reviewed exact 900-second activation-evidence lease. That lease can
outlive the already consumed challenge, but it is policy-bounded activation
evidence rather than renewed challenge freshness.

The post-restart outer activation is exactly
`dnai.compute.workload-recipient-activation.v3`. It binds the v4 verdict to the
full release lineage (`chain_id`, `domain`, `profile`, `cvm_id`, deployment
intent, release authority, ceremony nonce, and measurement policy), the
persisted measurement-policy-set and main-runtime-evidence digests, recipient
identity/report data, Phala app/compose/OS measurements, release policy, quote,
verifier, verdict digest, and bounded timestamps. Its explicit
`recipient_evidence_lease_expires_at` must equal activation expiry and the
recipient lease may last no more than 300 seconds. Missing and additional
fields fail closed in the browser parser. Its stable release commitment uses
domain
`dnai-wikigen/compute-workload-recipient-release/v2\0` and schema
`dnai.compute.workload-recipient-release.v2`; it additionally binds the v4
verification method, execution signer, contract, and exact recipient
attestation. A refreshed quote changes the activation commitment but cannot
change the release commitment unless one of those release-authority facts
changes.

Those facts enter the launch in three non-circular phases. Deployment intent,
ceremony nonce, measurement-policy-set, and the linked QVL measurement-policy
digest are authenticated bootstrap commitments. The main-runtime and
independent-metering CVM IDs are provider-assigned provisioning results and
must be copied only from the validated prepare response before the first
commit. Release-authority and main-runtime-evidence digests do not exist at
bootstrap: they remain empty, keep Compute activation unavailable, and may be
installed only through the authenticated post-measurement environment update
followed by the profile/service restart. An operator-supplied CVM ID or a
descriptor that precommits either post-measurement digest fails launch-intent
validation.

The bounded post-restart observation `O` projects exactly 20 public browser
environment values. Seven mandatory ceremony-lineage pins are the main-runtime
CVM ID, deployment-intent digest, release-authority digest, ceremony nonce,
measurement-policy-set digest, Compute-workload measurement-policy digest, and
main-runtime-evidence digest. The browser accepts the projection only as one
exact set derived from the same branded observation; a missing, additional, or
drifted value keeps upload disabled. These are public release bindings, not a
serialized capability or evidence that the fresh topology was deployed.

The production default is `UnavailableComputeWorkloadActivationProvider`.
Until an authenticated, activation-lease-valid QVL adapter supplies the verdict
and external expectations for the exact deployed recipient, the endpoint reports
blocked/unavailable and no ciphertext is persisted.

The `/attestation?context=compute_workload` response is producer evidence only
and always returns `verified: false`; it must never be presented as independent
Intel TDX verification.

## Durable custody and one-shot execution

The store uses directory-FD-anchored, no-follow file operations, authenticated
index state, restrictive owner/mode/link checks, a persistent lock FD, atomic
rename, and file/directory `fsync`. Exact replay returns the original receipt;
changed-body replay and nonce-tuple replay fail closed.

Execution authenticates a fresh signed QVL verdict-v4 within the recipient
evidence lease and recomputes the stored
stable recipient-release commitment from its exact recipient/report binding,
full release lineage, measurement-policy-set and main-runtime-evidence digests,
compose hash, app ID, OS image hash, release policy, QVL verifier, verification
method, execution signer, chain, and contract. The upload-time activation
commitment remains immutable proof of the historical quote; a refreshed quote
may differ without weakening the stable release comparison. Execution then
moves the authenticated record through
`sealed -> deleting`, durably removes the ciphertext before provider use,
decrypts and validates the private frame inside the CVM, yields only the
stripped private payload buffer to the future compiled recipe, and then
zeroizes both private payload and sealed-frame buffers. Explicit user deletion
uses the same durable consume path and never returns ciphertext.

## Still intentionally unavailable

- No provider API call is made by ingress.
- The public capability and every receipt keep
  `provider_dispatch_enabled: false`.
- The Tinker adapter remains unavailable until the separately documented
  restart/idempotency conformance gate is satisfied.
- The final Base Sepolia job authorization must sign both exact workload and
  manifest commitments, or sign the exact dispatch-intent commitment that
  transitively includes them. UI/API fields alone are not an onchain binding.
- The Compute ciphertext-upload route is capped at 1,425,408 request bytes by
  the shared ASGI pre-buffer body-limit policy. Declared oversize bodies,
  missing or false `Content-Length`, and chunked over-limit bodies fail before
  unbounded JSON buffering. Pydantic envelope limits remain a second line of
  defense.
