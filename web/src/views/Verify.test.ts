import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import type { VerificationContext } from "../lib/verificationContext";
import { Verify } from "./Verify";

const illustrative: VerificationContext = {
  schema: "dnai.browser-evidence-selection.v1",
  source: "arena_ranking",
  classification: "illustrative_only",
  challengeId: "atlas-denoise-01",
  challengeVersion: null,
  rank: 1,
  submissionId: null,
  candidateCommitment: null,
  ladder: null,
  workerClaim: null,
};

const projection: VerificationContext = {
  schema: "dnai.browser-evidence-selection.v1",
  source: "arena_ranking",
  classification: "projection_only_no_execution_evidence",
  challengeId: "dnaseq-variant-qc-safe-ir",
  challengeVersion: "1.0.0",
  rank: 2,
  submissionId: "sub_public_01",
  candidateCommitment: `sha256:${"b".repeat(64)}`,
  ladder: Object.freeze({ stepIndex: 4, denominator: 20, improvementSteps: 3 }),
  workerClaim: null,
};

const workerReported: VerificationContext = {
  ...projection,
  classification: "worker_reported_qvl_binding_not_independently_verified",
  workerClaim: Object.freeze({
    outcome: "completed",
    runtimePolicyCommitment: `sha256:${"1".repeat(64)}`,
    challengeManifestHash: "2".repeat(64),
    composeHash: "3".repeat(64),
    osImageHash: "4".repeat(64),
    quoteSha256: `sha256:${"5".repeat(64)}`,
    verifierAddress: `0x${"6".repeat(40)}`,
    verdictDigest: `0x${"7".repeat(64)}`,
    teeSignerAddress: `0x${"8".repeat(40)}`,
    registryAddress: `0x${"9".repeat(40)}`,
    chainId: 84532,
  }),
};

const computeHash: VerificationContext = {
  schema: "dnai.browser-evidence-selection.v1",
  source: "compute_receipt_hash",
  classification: "service_reported_hash_only_not_receipt",
  receiptSha256: `sha256:${"a".repeat(64)}`,
  operation: "inference",
  resultPolicy: "bounded_summary_receipt",
  dispatchStatus: "not_dispatched",
  providerAuthoritativeSettlement: false,
  rawInputPersisted: false,
  rawOutputPersisted: false,
};

const contractDealResult: VerificationContext = {
  schema: "dnai.browser-evidence-selection.v1",
  source: "deal_result",
  classification: "contract_reported_result_not_independently_verified",
  roomId: "17",
  state: "Evaluated",
  scoreBand: "High",
  resultCommitment: `0x${"1".repeat(64)}`,
  composeBinding: `0x${"2".repeat(64)}`,
  evaluatorPolicyCommitment: `0x${"3".repeat(64)}`,
  attestationEvidenceCommitment: `0x${"4".repeat(64)}`,
  chainId: 84532,
  contractAddress: `0x${"5".repeat(40)}`,
  independentlyVerifiedByBrowser: false,
  rawQuoteAvailable: false,
  intelCollateralVerifiedByBrowser: false,
};

const illustrativeDealResult: VerificationContext = {
  ...contractDealResult,
  classification: "illustrative_only",
  contractAddress: null,
};

function renderSelected(context?: VerificationContext): string {
  return renderToString(() => createComponent(Verify, {
    selectedEvidence: context,
    clearSelectedEvidence: () => undefined,
  }));
}

describe("Verify selected evidence projection", () => {
  it("keeps the generic workbench independent when no source row is selected", () => {
    const html = renderSelected();
    expect(html).not.toContain("IN-MEMORY PUBLIC PROJECTION");
    expect(html).toContain("Six levels—not one boolean.");
    expect(html).toContain("Dynamic Email Oracle readiness");
    expect(html).toContain("Fail closed · no release identity");
    expect(html).toContain("does not send email, generate or reveal an OTP");
    expect(html).toContain("LIVE READ PATH · BLOCKED");
    expect(html).toContain("READ ONLY");
    expect(html).toContain("modeled-receipt:not-a-hardware-signature");
  });

  it("renders illustrative context as a named, keyboard-focusable region", () => {
    const html = renderSelected(illustrative);
    expect(html).toContain('role="region" aria-labelledby="selected-evidence-title" tabindex="-1"');
    expect(html).toContain("Illustrative · no execution");
    expect(html).toContain("No program ran, no reward exists");
    expect(html).toContain("No released version");
    expect(html).toContain("Clear selected context");
  });

  it("does not promote a projection-only row into execution evidence", () => {
    const html = renderSelected(projection);
    expect(html).toContain("Projection only · no execution evidence");
    expect(html).toContain("no row-level execution evidence");
    expect(html).toContain("sub_public_01");
    expect(html).toContain("Selecting this row never advances the six-level ladder or seeds the receipt editor.");
  });

  it("shows worker-reported commitments without claiming browser verification", () => {
    const html = renderSelected(workerReported);
    expect(html).toContain("Worker-reported · not independently verified");
    expect(html).toContain("QVL signer claim");
    expect(html).toContain("has not received the raw quote");
    expect(html).toContain("0</strong><span>QVL verified");
    expect(html).toContain("Not QVL verified");
    expect(html).not.toContain('class="cvm-evidence-state verified"');
    expect(html).toContain("Quote verified");
    expect(html).toContain('class="layer-state pending"');
  });

  it("renders contract-reported Deal Room commitments without promoting them to QVL or Intel proof", () => {
    const html = renderSelected(contractDealResult);
    expect(html).toContain("Deal Room 17 result projection");
    expect(html).toContain("Room 17 contract-reported public fields");
    expect(html).toContain("Contract-reported · not independently verified");
    expect(html).toContain("Attestation evidence commitment");
    expect(html).toContain(contractDealResult.attestationEvidenceCommitment);
    expect(html).toContain("has not authenticated the result-verifier or QVL signatures");
    expect(html).toContain("Intel collateral verified by browser");
    expect(html).toContain("false");
    expect(html).not.toContain("Intel collateral verified by browser</small><strong>true");
  });

  it("keeps modeled Deal Room cards explicitly illustrative in Trust Center", () => {
    const html = renderSelected(illustrativeDealResult);
    expect(html).toContain("Illustrative Deal Room 17 result");
    expect(html).toContain("Designed sample for public room 17");
    expect(html).toContain("Modeled preview · no contract source");
    expect(html).toContain("No contract reported them, no evaluator ran");
    expect(html).not.toContain("Contract-reported · not independently verified");
  });

  it("renders a Compute service hash without project or job identity and without seeding a receipt", () => {
    const html = renderSelected(computeHash);
    expect(html).toContain("Hash only · receipt body absent");
    expect(html).toContain(computeHash.receiptSha256);
    expect(html).toContain("project and job identity intentionally omitted");
    expect(html).toContain("not a receipt body");
    expect(html).toContain("modeled-receipt:not-a-hardware-signature");
    expect(html).not.toContain("job_private_identity");
  });
});
