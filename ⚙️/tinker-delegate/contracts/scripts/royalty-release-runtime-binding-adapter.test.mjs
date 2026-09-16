import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  normalizeFinalReleaseAuthorityCore,
} from "../../../../scripts/execution-policy-release-core.mjs";
import {
  knownVector,
} from "../../../../scripts/execution-policy-release-core.fixture.mjs";
import {
  projectRoyaltySettlementReleaseBinding,
} from "./royalty-release-phase-plan.mjs";
import {
  projectRoyaltyRuntimeBindingAdapter,
  pythonRoyaltyRuntimeBindingCommitment,
  royaltyRuntimeBindingAdapterReceiptSha256,
} from "./royalty-release-runtime-binding-adapter.mjs";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const VECTOR_PATH = path.resolve(
  SCRIPT_DIR,
  "../../tests/fixtures/royalty_release_binding_adapter_v1.json",
);
const VECTOR = JSON.parse(fs.readFileSync(VECTOR_PATH, "utf8"));

function currentFinalAuthority() {
  const value = knownVector();
  Object.assign(value.requested_features, {
    collaboration: true,
    collaboration_execution: true,
    royalty_settlement: true,
  });
  value.collaboration_execution.enabled = true;
  return normalizeFinalReleaseAuthorityCore(value);
}

test("frozen JS to Python Royalty runtime binding KAT is exact", () => {
  assert.equal(
    VECTOR.schema,
    "dnai.royalty-settlement-runtime-binding-adapter-known-answer.v1",
  );
  assert.equal(
    VECTOR.truth_status,
    "synthetic_cross_language_known_answer_never_live_release_authority",
  );
  const finalAuthority = currentFinalAuthority();
  const sourceBinding = projectRoyaltySettlementReleaseBinding(finalAuthority);
  const projected = projectRoyaltyRuntimeBindingAdapter({
    finalReleaseAuthorityV4: finalAuthority,
    reconciliationReceipt: VECTOR.adapter_receipt.reconciliation_receipt,
    royaltySettlementReleaseBinding: sourceBinding,
  });
  assert.deepEqual(projected, VECTOR.adapter_receipt);
  assert.equal(
    projected.runtime_binding_commitment,
    "sha256:1963adbf72508148a6c0e8795b398b8195b5ee62cc638f67509f4ad4c0c53f63",
  );
  assert.equal(
    projected.runtime_binding.royalty_qvl_policy_commitment,
    "0xac84767f084ec979b282d1ccf07fd3e1807a3d20d373852f24df474bf1273797",
  );
  assert.equal(
    royaltyRuntimeBindingAdapterReceiptSha256(projected),
    VECTOR.adapter_receipt_sha256,
  );
  assert.equal(
    pythonRoyaltyRuntimeBindingCommitment(projected.runtime_binding),
    projected.runtime_binding_commitment,
  );
});

test("adapter rejects H, runtime, and source authority drift", () => {
  const finalAuthority = currentFinalAuthority();
  const sourceBinding = projectRoyaltySettlementReleaseBinding(finalAuthority);
  const wrongHistory = structuredClone(
    VECTOR.adapter_receipt.reconciliation_receipt,
  );
  wrongHistory.royalty_release_history_receipt_sha256 =
    `sha256:${"ef".repeat(32)}`;
  assert.throws(
    () => projectRoyaltyRuntimeBindingAdapter({
      finalReleaseAuthorityV4: finalAuthority,
      reconciliationReceipt: wrongHistory,
      royaltySettlementReleaseBinding: sourceBinding,
    }),
    /exact reconciled final-authority v4, H, and source binding/,
  );

  const wrongRuntime = structuredClone(VECTOR.adapter_receipt);
  wrongRuntime.runtime_binding.owner_address =
    "0x00000000000000000000000000000000000000ff";
  wrongRuntime.runtime_binding_commitment =
    pythonRoyaltyRuntimeBindingCommitment(wrongRuntime.runtime_binding);
  assert.throws(
    () => royaltyRuntimeBindingAdapterReceiptSha256(wrongRuntime),
    /adapter receipt is invalid/,
  );

  const wrongReceiptSource = structuredClone(VECTOR.adapter_receipt);
  wrongReceiptSource.source_binding.release_sha = "f".repeat(40);
  assert.throws(
    () => royaltyRuntimeBindingAdapterReceiptSha256(wrongReceiptSource),
    /adapter receipt is invalid/,
  );

  const wrongReceiptReconciliation = structuredClone(VECTOR.adapter_receipt);
  wrongReceiptReconciliation.reconciliation_receipt.release_sha = "f".repeat(40);
  assert.throws(
    () => royaltyRuntimeBindingAdapterReceiptSha256(
      wrongReceiptReconciliation,
    ),
    /adapter receipt is invalid/,
  );

  const wrongSource = structuredClone(sourceBinding);
  wrongSource.royalty_release_authority.qvl_verifier =
    wrongSource.royalty_release_authority.settlement_verifier;
  assert.throws(
    () => projectRoyaltyRuntimeBindingAdapter({
      finalReleaseAuthorityV4: finalAuthority,
      reconciliationReceipt:
        VECTOR.adapter_receipt.reconciliation_receipt,
      royaltySettlementReleaseBinding: wrongSource,
    }),
    /differs from current final-authority v4 or H/,
  );
});
