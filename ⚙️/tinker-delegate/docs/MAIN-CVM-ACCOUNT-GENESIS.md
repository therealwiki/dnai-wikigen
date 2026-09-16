# Canonical main-CVM account genesis

Status: source/runtime primitive implemented and locally testable; no provider
account, current project-owned CVM, independent QVL verdict, or production
activation is claimed by this document.

The canonical main descriptor contains two measured, disabled one-shot
services:

- `mailbox-genesis`, under the `mailbox-genesis` profile;
- `tinker-account-genesis`, under the `tinker-account-genesis` profile.

They are services inside the existing `main_runtime_cvm`, not additional CVMs.
The release topology therefore remains exactly seven CVMs: the main runtime,
five purpose-separated QVL CVMs, and independent metering.

## Initial fail-closed state

Neither profile is selected during `bootstrap_provision`. The ordinary
long-running services retain their production controls:

- `oracle` has `ORACLE_AUTO_GENESIS=false`, on-chain consumer authorization
  enabled, and the credential-provisioning endpoint disabled;
- `delegate` has `TINKER_BOOTSTRAP_SIGNUP=false`,
  `TINKER_BOOTSTRAP_FAIL_OPEN=false`, card/add-balance disabled, and no raw
  upstream API key in its environment;
- both one-shot services have `restart: "no"`, read-only root filesystems,
  all ambient capabilities dropped, no host ports, and only the internal
  `tee-net` network;
- the mailbox service can write `oracle-data` but cannot mount
  `delegate-data`; it is the only writer of `mailbox-genesis-evidence`;
- the account service can write `delegate-data` but mounts the encrypted
  mailbox handoff read-only and cannot mount `oracle-data`; it is the only
  writer of `tinker-account-genesis-evidence`;
- the mailbox service mounts `tinker-account-genesis-evidence` read-only only
  so it can validate the complete account retirement record before deleting
  the encrypted handoff; the account service cannot mount mailbox evidence.

Adding the profiles to the measured descriptor does not authorize them to run.
The current nonlive Phala bootstrap authority still authorizes only the normal
initial service set. A separate reviewed post-measurement account-genesis
authority and exact environment allowlist are required before either profile
can be selected.

## Immutable account binding

The release renderer copies
`deploymentIntent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment`
directly into
`TINKER_ACCOUNT_BINDING_EXPECTED_COMMITMENT`. It is a literal measured
descriptor value, not `${...}` interpolation and not a mutable Phala
environment update.

The renderer also requires the exact private canonical ceremony receipt at
`.release/tinker-account-binding-ceremony.receipt.json`. It validates the
receipt's fresh two-reviewer shape, deployment-intent binding, Base Sepolia
constants, account commitment, reviewer lineage, and domain-separated
self-digest. It then copies the exact canonical bytes into the output at mode
`0600` and renders that self-digest as the same immutable literal in both
profiles:

- `ORACLE_GENESIS_BINDING_CEREMONY_RECEIPT_SHA256`;
- `TINKER_ACCOUNT_GENESIS_BINDING_CEREMONY_RECEIPT_SHA256`.

This Python validation is structural and digest binding, not signature
verification. The canonical Node ceremony-check replay remains a separate
release gate and must independently verify both reviewer signatures.

Before it creates a claim file or calls any provider surface, the account
service:

1. removes two private 32-byte shares from its process environment;
2. derives the opaque binding root with the shared
   `dnai.tinker-account-binding.v1` HKDF construction;
3. derives the public EVM commitment;
4. wipes the mutable share buffers;
5. rejects the run if the result differs from the deployment-intent literal.

The public commitment does not commit a provider account identifier. Later
attested evidence must establish that the measured service bound the opaque
handle to the provider account it created. Receipts never expose a share,
binding root, provider account id, mailbox, API key, credential/session value,
or a hash derived from those secrets.

## One-shot flow

The intended account-genesis phase selects both profiles together:

```text
mailbox-genesis
  create provider mailbox once
  seal mailbox credentials to oracle-data
  write encrypted same-CVM handoff
  publish bounded mailbox receipt and permanent retirement marker
  serve an internal bearer-protected OTP API for a bounded window
        |
        v
tinker-account-genesis
  verify shares against immutable deployment-intent commitment
  verify running app/compose/OS identity against reviewed lineage
  decrypt mailbox handoff only inside the CVM
  attempt signup/onboarding/API-key creation once
  round-trip the sealed API key from delegate-data
  publish bounded account receipt and permanent retirement marker
        |
        v
mailbox-genesis observes retirement, deletes the encrypted handoff, and exits
```

The temporary mailbox API has no host port. It uses the same dstack-derived
runtime bearer as the account service, under the exact
`oracle/runtime-auth` key path. Its on-chain authorization switch remains
`ORACLE_AUTH_REQUIRED=false`; that switch is not reused as HTTP bearer
authorization. Instead `ORACLE_RUNTIME_AUTH_REQUIRED=true` is mandatory, its
explicit token is empty, and the bearer is derived from dstack. Empty bearer
tokens are rejected. Credential provisioning is disabled, and the profile
does not weaken the normal oracle. The normal oracle must be restarted under a
later reviewed phase so it loads the newly sealed credential store; a
successful one-shot receipt does not itself activate ordinary runtime.

## Evidence boundary

Both services create an exclusive `claim.json` before the first external side
effect. Receipt and retirement files are create-only, mode `0600`, under a
mode-`0700` evidence directory. Creation rejects symlinks, hard links, wrong
ownership or mode, and retained-directory/path identity changes; file and
directory metadata are synced before success. The claim is intentionally
never removed.

This means:

- a second invocation is rejected;
- a bounded failure is retired, not automatically retried;
- a crash after the claim leaves an indeterminate one-shot state that requires
  a fresh reviewed release rather than manual replay;
- Docker restart policy cannot repeat provider-side signup;
- provider error bodies are not copied to receipt or retirement artifacts.

The mailbox receipt can say only whether mailbox creation, sealed credential
round-trip, and encrypted handoff creation were confirmed. The account receipt
can say only whether upstream account existence and a sealed API-key
round-trip returned the exact JSON boolean `true` for that attempt; strings and
integers such as `"false"` and `1` are rejected. Injected clocks are accepted
only as exact nonnegative JSON-safe integers, excluding booleans. Both receipts
state:

- `raw_secret_egress: false`;
- `live_traffic_authorized: false`;
- `independent_qvl_verified_by_profile: false`;
- the exact release, deployment intent, reviewer status, main CVM/app/compose/OS
  identity, account-genesis authorization, measurement-policy digest, and
  already reviewed main-QVL verdict digest.

Before removing the handoff, the mailbox watcher reads a stable, bounded,
canonical `retirement.json` from the account evidence volume and validates its
complete schema, status, retry policy, lineage, account commitment, reviewer
tuple, timestamp, and raw-secret projection. A partial or substituted file
cannot trigger deletion. Handoff deletion opens the retained parent and file
without following symlinks, unlinks the exact name, syncs the directory, and
then proves both retained-object unlink state and pathname absence. Any
identity ambiguity fails closed.

Those self-produced receipts are not Intel TDX or QVL evidence. The external
ceremony must independently authenticate the quote and QVL verdict, compare
the complete release tuple, verify both create-only receipts and retirement
markers, prove the encrypted handoff was deleted, and keep all contracts
halted on any mismatch.

## Activation stop rules

Do not select these profiles unless all of the following exist:

1. a fresh operator-owned seven-contract ledger;
2. a fresh exact-seven CVM launch completion receipt;
3. an independently verified main-CVM quote under the exact release policy;
4. a two-reviewer account-genesis authorization bound to the exact descriptor
   and one-time attempt;
5. a canonical fresh account-binding ceremony receipt whose Node ceremony
   replay verifies both reviewers and whose self-digest equals the immutable
   literal rendered into both profiles;
6. two private shares whose derived commitment equals the literal rendered
   deployment-intent commitment;
7. a provider-approved account-creation route;
8. exact encrypted environment authority for the three post-measurement
   evidence digests and two private shares.

After either one-shot exits, keep both profiles disabled permanently. Do not
enable live traffic, funding, inference, training, contract unhalt, or
Cloudflare release based on these receipts alone.
