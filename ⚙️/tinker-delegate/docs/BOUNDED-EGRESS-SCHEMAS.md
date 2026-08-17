# Bounded egress schemas

Private-reward services maintain two deliberately different representations:

1. **Internal enforcement state** retains exact values needed for cryptographic
   integrity, decryption, query caps, and differential-privacy accounting.
2. **Public projections** are one-way, lossy schemas. They contain only declared
   public policy, coarse bands, opaque commitments, released reward bands, and
   the minimum status required to continue or fail closed.

An object being JSON-serializable does not make it public. In particular, a
sealed-dataset transport manifest is internal metadata even though a storage
backend persists it as JSON. API and CLI responses must use the receipt or an
explicit `to_public_dict()` projection.

## Sealed datasets

`build_manifest()` retains exact plaintext size, exact chunk topology/nonces,
wrapped recipient envelopes, and an operational storage ref. These values are
required to authenticate and decrypt the ciphertext. The internal manifest must
not be copied into an API response.

`public_manifest_projection()` and `seal_receipt()` instead expose:

- `plaintext_size_band` and `chunk_count_band`, using fixed code-defined bands;
- `storage_ref_hash`, a domain-separated opaque commitment, never a local path,
  private bucket, signed URL, or other operational ref;
- cryptographic dataset/manifest commitments and recipient public-key hashes;
- declared task/sensitivity labels and the fixed public schema version.

`publish_dataset()` and `fetch_decrypt_dataset()` follow the same rule. A caller
that needs to continue an internal local flow retains `backend.ref_for(dataset_id)`
inside the boundary. The public publish receipt is evidence, not a storage
capability. A successful fetch receipt reports only `plaintext_size_band`.

## Hidden holdout

`HiddenHoldoutSet.partition_counts` remains exact for enforcing minimums and
selecting records in the TEE. `HoldoutPublicManifest.partition_counts` retains
its compatibility key, but its values are disclosure labels (`small_1_to_8`,
`medium_9_to_64`, and so on), marked by
`partition_count_disclosure = banded_v1`. The `split_commitment` binds the exact
private split and declared policy without revealing record IDs or cardinalities.

The split fractions, minimums, and query caps under `policy` are exact because
they are caller-declared public policy committed before evaluation, not facts
inferred from the private dataset.

## Thresholdout

`ThresholdoutRelease` and `ThresholdoutGate` retain `used_holdout` and exact
holdout-access counts internally for charging and audit. Public release records
omit both. They expose only the released step index, its public denominator,
query index, `has_release`, and `budget_status` (`available` or `exhausted`).

The public gate manifest likewise omits access counts and exact epsilon spent.
This prevents an adaptive caller from learning whether an individual private
holdout gap crossed the noisy branch threshold. Budget exhaustion remains public
because the service must explain a fail-closed no-release result.

## Regression rule

Every schema change in this area needs an adversarial equivalence test: choose
distinct private inputs with different exact internal values, normalize only
opaque commitments, and prove their public projections have the same bounded
shape. A test that merely searches for a plaintext marker is insufficient;
metadata and branch decisions can be sensitive even when raw plaintext is absent.
