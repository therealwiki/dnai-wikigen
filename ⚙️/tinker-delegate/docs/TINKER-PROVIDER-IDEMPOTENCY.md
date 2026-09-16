# Tinker provider execution and ambiguity gate

Audit date: 2026-07-23

Local transport follow-up: 2026-07-21. This follow-up made no provider request
and used no provider credential.

Audited release: the reproducibly locked `tinker==0.22.7` Python SDK. The
official Tinker API documentation and the source published by Thinking
Machines Lab were treated as authoritative. No live provider credential or
undocumented server behavior was used to fill a gap.

Upstream `tinker==0.23.2` was the current public SDK on 2026-07-21 after this
reproducible lock was selected (official repository `main` at
`bbb3dcb69065b6cac33adcac7ee506337ce0de6f`). A no-credential isolated
API/source spot-check found that its public
`ServiceClient.create_lora_training_client`, paid `TrainingClient` steps,
`SamplingClient`, and `RestClient.list_training_runs` signatures still do not
expose a caller-stable dispatch/idempotency/recovery key. Its generated
low-level resources still accept `idempotency_key`, and automatic retry keys
remain random `stainless-python-retry` UUIDs. This spot-check does not make
0.23.2 part of the release and does not close the crash-recovery contract; the
runtime remains locked to 0.22.7 until an upgrade is separately reviewed and
reproduced.

## Decision

The release does **not** claim provider-side idempotent replay. Instead, the
production adapter implements a stricter at-most-once local attempt boundary:
it durably checkpoints `provider_attempt_checkpointed` immediately before the
first allowlisted provider request. If the process loses a conclusive bounded
result after that checkpoint, the job becomes the terminal
`provider_outcome_ambiguous` state. It is never automatically redispatched and
its encrypted workload remains sealed for separately attested reconciliation.

The adapter, request grammar, SDK source, endpoint commitment, offline
tokenizer, and these crash semantics are frozen by provider release
`sha256:4264a2226ac9c850d8f053c98ac90d0f6dcbc58702919899384a9b2442b35631`.
This is an implemented release gate, not evidence that a provider or CVM is
currently live. Public dispatch remains fail-closed unless the exact release
configuration validates and the worker publishes a fresh authenticated local
heartbeat. Browser and customer credentials never satisfy that gate.

This is narrower than saying that Tinker has no idempotency machinery. Version
0.22.7's generated transport accepts an `idempotency_key` on low-level POST
methods and sends `X-Idempotency-Key`. The gap is that the supported public
workflow does not let this release bind the worker's durable `dispatchId` to
model creation and every paid training or sampling operation, and the official
contract does not specify the server guarantees required to safely infer that
behavior.

## Exact evidence

| Surface | What exists in 0.22.7 | Why it is insufficient for this release |
| --- | --- | --- |
| Generated `AsyncServiceResource.create_session` | Accepts a caller-supplied `idempotency_key`. | The server retention, key scope, body-conflict, concurrent replay, and response replay contract is not documented or authenticated. |
| `ServiceClient.create_lora_training_client` | Accepts model configuration and `user_metadata`. | No caller-supplied `dispatch_id`, idempotency key, request ID, or recovery token. An ambiguous connection loss can happen before the returned training-run ID is durably journaled. |
| Generated `AsyncModelsResource.create` | Accepts an `idempotency_key`; the generated client maps it to `X-Idempotency-Key`. | It is a low-level HTTP hook, not a documented whole-dispatch contract. The public high-level call does not plumb the worker key into it. |
| Generated `AsyncServiceResource.create_sampling_session` | Does not expose an `idempotency_key` argument. In 0.22.7, its generic `extra_headers` escape hatch can carry `X-Idempotency-Key`, and a local mock-transport test proves the generated client does not overwrite that header. | This proves only the bytes emitted by this pinned client. It does not prove that the authenticated provider stores the key, rejects a changed body, executes once under concurrency, or replays the same sampling-session ID after a crash. |
| `TrainingClient.forward_backward`, `optim_step`, checkpoint writes, and sampling | Return futures and internally submit request IDs/sequence IDs. | The public methods do not accept the worker's stable key. A request ID becomes useful only after the client receives and durably records it, leaving the process-kill/response-loss window unresolved. |
| `RestClient.list_training_runs` | Lists owned or accessible runs and may return `user_metadata`; it can filter by project. | There is no exact server-side lookup by metadata/dispatch ID, no uniqueness constraint, and no documented consistent read-after-write guarantee. Scanning can detect candidates but cannot prove that creating another run is safe. |
| `get_training_run` and checkpoint APIs | Recover a known provider run/checkpoint ID. | The ID must already be known. Checkpoint resume creates a new training client and only helps after a durable checkpoint; it cannot resolve an ambiguous earlier mutation. |
| Generated automatic retry key | A fresh `stainless-python-retry-<uuid>` is generated when a low-level non-GET call has no explicit key. | It is stable only within that generated request object's retry loop. A new public-call attempt or restarted process has no binding to the worker's `dispatchId`. |

The official public documentation describes `APIFuture.result()`, training-run
listing, run lookup, and checkpoint resume, but does not document:

- idempotency-key retention duration;
- key namespace and credential/project scope;
- atomic replay of the original response after a committed-but-disconnected
  request;
- same-key/different-payload conflict behavior;
- concurrency behavior for simultaneous requests using one key;
- a supported way to reconstruct a future from a caller key after restart; or
- an atomic provider-level operation representing this product's entire
  compiled recipe.

Without those semantics, wrapping private SDK resources would only move the
uncertainty. It would not prove that retrying cannot double-create a model,
repeat an optimizer mutation, repeat billable sampling, or lose the bounded
usage result.

The repository-local release now also binds the exact adapter source and SDK
source hash, the low-level request allowlist, endpoint hash, offline tokenizer
bundle, dstack-only sealed credential path, Base Sepolia vault/runtime pins,
recipient-QVL lineage, and exact workload/manifest commitments. The provider
heartbeat proves only authenticated local process presence; it is explicitly
not Intel TDX evidence and cannot replace the separate release/attestation
chain.

A request key is still sent as a deterministic request commitment where the
pinned transport permits it, but neither the journal, API, nor receipt labels
that key as an upstream replay guarantee. A local mock server or self-asserted
fixture cannot set `idempotent_provider_replay_claimed` to true.

Primary references:

- [Tinker ServiceClient API](https://tinker-docs.thinkingmachines.ai/tinker/api-reference/serviceclient/)
- [Tinker TrainingClient API](https://tinker-docs.thinkingmachines.ai/tinker/api-reference/trainingclient/)
- [Tinker RestClient API](https://tinker-docs.thinkingmachines.ai/tinker/api-reference/restclient/)
- [Tinker APIFuture API](https://tinker-docs.thinkingmachines.ai/tinker/api-reference/apifuture/)
- [Thinking Machines Lab Tinker SDK source](https://github.com/thinking-machines-lab/tinker)

## Required proof before claiming replay-safe redispatch

The current at-most-once adapter does not require or claim these semantics.
Automatic redispatch must remain false unless a future pinned SDK and official
server contract provide either one atomic dispatch primitive or complete
per-step recovery. At minimum, that future contract must guarantee:

1. A caller-supplied stable key for model creation and every billable or
   state-mutating recipe step.
2. A documented retention horizon longer than the product's maximum recovery
   window, plus explicit credential/project scoping.
3. Replay of the same result/provider object for the same key and identical
   canonical payload, including after process restart.
4. Rejection of the same key with a different payload.
5. One mutation under concurrent same-key submissions.
6. An exact status/result lookup by caller key, or a response-replay operation
   that closes the crash-before-provider-ID-persistence window.
7. A bounded, provider-authenticated usage result suitable for the existing
   metering envelope, or an explicitly modeled non-authoritative derivation.

Credentialed release tests must then inject a disconnect and process kill at
each boundary: before send, after server commit but before response, after the
provider request/future ID is returned but before local persistence, after
result completion, and during concurrent replay. Each replay must recover the
same provider IDs and byte-identical bounded result; altered-payload replay
must fail, and provider-side accounting must show one mutation. Those tests
belong in an isolated paid staging project and must not run in ordinary CI.

The local no-network audit in `tests/test_tinker_provider_contract.py` pins the
current SDK surface so a future SDK upgrade cannot be mistaken for a completed
server-semantics review.
