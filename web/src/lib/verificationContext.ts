import type { ArenaExecutionProvenance } from "./arena";
import type { ComputeJob } from "./compute";
import type { ChainDeal } from "./contract";

type Sha256Digest = `sha256:${string}`;
type HexDigest = `0x${string}`;
type Address = `0x${string}`;

export type VerificationContextClassification =
  | "illustrative_only"
  | "projection_only_no_execution_evidence"
  | "worker_reported_qvl_binding_not_independently_verified"
  | "contract_reported_result_not_independently_verified"
  | "service_reported_hash_only_not_receipt";

interface VerificationContextBase {
  readonly schema: "dnai.browser-evidence-selection.v1";
  readonly classification: VerificationContextClassification;
}

interface ArenaLadderProjection {
  readonly stepIndex: number;
  readonly denominator: number;
  readonly improvementSteps: number;
}

interface ArenaWorkerClaim {
  readonly outcome: "completed" | "failed";
  readonly runtimePolicyCommitment: Sha256Digest;
  readonly challengeManifestHash: string;
  readonly composeHash: string;
  readonly osImageHash: string;
  readonly quoteSha256: Sha256Digest;
  readonly verifierAddress: Address;
  readonly verdictDigest: HexDigest;
  readonly teeSignerAddress: Address;
  readonly registryAddress: Address;
  readonly chainId: 84532;
}

export interface ArenaRankingVerificationContext extends VerificationContextBase {
  readonly source: "arena_ranking";
  readonly classification:
    | "illustrative_only"
    | "projection_only_no_execution_evidence"
    | "worker_reported_qvl_binding_not_independently_verified";
  readonly challengeId: string;
  readonly challengeVersion: string | null;
  readonly rank: number;
  readonly submissionId: string | null;
  readonly candidateCommitment: Sha256Digest | null;
  readonly ladder: ArenaLadderProjection | null;
  readonly workerClaim: ArenaWorkerClaim | null;
}

export interface ComputeReceiptHashVerificationContext extends VerificationContextBase {
  readonly source: "compute_receipt_hash";
  readonly classification: "service_reported_hash_only_not_receipt";
  readonly receiptSha256: Sha256Digest;
  readonly operation: "inference" | "training";
  readonly resultPolicy: "bounded_summary_receipt" | "score_band_hash";
  readonly dispatchStatus: "not_dispatched";
  readonly providerAuthoritativeSettlement: false;
  readonly rawInputPersisted: false;
  readonly rawOutputPersisted: false;
}

export interface DealResultVerificationContext extends VerificationContextBase {
  readonly source: "deal_result";
  readonly classification:
    | "illustrative_only"
    | "contract_reported_result_not_independently_verified";
  readonly roomId: string;
  readonly state: "Evaluated" | "Accepted" | "Rejected";
  readonly scoreBand: ChainDeal["scoreBand"];
  readonly resultCommitment: HexDigest;
  readonly composeBinding: HexDigest;
  readonly evaluatorPolicyCommitment: HexDigest;
  readonly attestationEvidenceCommitment: HexDigest;
  readonly chainId: 84532;
  readonly contractAddress: Address | null;
  readonly independentlyVerifiedByBrowser: false;
  readonly rawQuoteAvailable: false;
  readonly intelCollateralVerifiedByBrowser: false;
}

/**
 * One public-only, in-memory selection carried from a product row to Verify.
 * The union is deliberately closed: authenticated project/job identity,
 * modeled contestant identity, raw evidence, secrets, and arbitrary display
 * text cannot be added by a caller.
 */
export type VerificationContext =
  | ArenaRankingVerificationContext
  | DealResultVerificationContext
  | ComputeReceiptHashVerificationContext;

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const PUBLIC_DIGEST = /^(?:sha256:|0x)?[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const HEX_DIGEST = /^0x[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;

function identifier(value: unknown, label: string): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new Error(`${label} is not a bounded public identifier`);
  }
  return value;
}

function version(value: unknown): string {
  if (typeof value !== "string" || !VERSION.test(value)) {
    throw new Error("Arena challenge version is not bounded public text");
  }
  return value;
}

function positiveInteger(value: unknown, label: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > maximum) {
    throw new Error(`${label} is not a bounded positive integer`);
  }
  return Number(value);
}

function nonnegativeInteger(value: unknown, label: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0 || Number(value) > maximum) {
    throw new Error(`${label} is not a bounded nonnegative integer`);
  }
  return Number(value);
}

function sha256Digest(value: unknown, label: string): Sha256Digest {
  if (typeof value !== "string") throw new Error(`${label} is not a SHA-256 digest`);
  const normalized = value.toLowerCase();
  if (!SHA256.test(normalized)) throw new Error(`${label} is not a SHA-256 digest`);
  return normalized as Sha256Digest;
}

function publicDigest(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} is not a public 32-byte digest`);
  const normalized = value.toLowerCase();
  if (!PUBLIC_DIGEST.test(normalized)) throw new Error(`${label} is not a public 32-byte digest`);
  return normalized;
}

function publicAddress(value: unknown, label: string): Address {
  if (typeof value !== "string") throw new Error(`${label} is not an address`);
  const normalized = value.toLowerCase();
  if (!ADDRESS.test(normalized)) throw new Error(`${label} is not an address`);
  return normalized as Address;
}

function hexDigest(value: unknown, label: string): HexDigest {
  if (typeof value !== "string") throw new Error(`${label} is not a bytes32 digest`);
  const normalized = value.toLowerCase();
  if (!HEX_DIGEST.test(normalized)) throw new Error(`${label} is not a bytes32 digest`);
  return normalized as HexDigest;
}

function uint256Decimal(value: unknown, label: string): string {
  if (typeof value !== "bigint" || value < 0n || value >= (1n << 256n)) {
    throw new Error(`${label} is not a uint256 value`);
  }
  return value.toString(10);
}

function ladderProjection(value: ArenaRankingVerificationInput["ladder"]): ArenaLadderProjection | null {
  if (!value) return null;
  const denominator = positiveInteger(value.denominator, "Arena Ladder denominator", 1_000_000);
  const stepIndex = nonnegativeInteger(value.stepIndex, "Arena Ladder step", denominator);
  return Object.freeze({
    stepIndex,
    denominator,
    improvementSteps: nonnegativeInteger(value.improvementSteps, "Arena improvement count", 1_000_000),
  });
}

function workerClaim(provenance: Extract<ArenaExecutionProvenance, { status: "worker_reported" }>): ArenaWorkerClaim {
  if (provenance.chain_id !== 84532) throw new Error("Arena worker chain ID is not Base Sepolia");
  return Object.freeze({
    outcome: provenance.outcome,
    runtimePolicyCommitment: sha256Digest(provenance.runtime_policy_commitment, "Arena runtime policy"),
    challengeManifestHash: publicDigest(provenance.challenge_manifest_hash, "Arena challenge manifest"),
    composeHash: publicDigest(provenance.compose_hash, "Arena compose hash"),
    osImageHash: publicDigest(provenance.os_image_hash, "Arena OS image hash"),
    quoteSha256: sha256Digest(provenance.quote_sha256, "Arena quote digest"),
    verifierAddress: publicAddress(provenance.verifier_address, "Arena QVL signer"),
    verdictDigest: hexDigest(provenance.verdict_digest, "Arena verdict digest"),
    teeSignerAddress: publicAddress(provenance.tee_signer_address, "Arena TEE signer"),
    registryAddress: publicAddress(provenance.challenge_registry_address, "Arena challenge registry"),
    chainId: 84532,
  });
}

export interface ArenaRankingVerificationInput {
  readonly challengeId: string;
  readonly challengeVersion?: string;
  readonly rank: number;
  readonly evidence: "illustrative" | "none" | "worker_reported";
  readonly submissionId?: string;
  readonly candidateCommitment?: string;
  readonly ladder?: {
    readonly stepIndex: number;
    readonly denominator: number;
    readonly improvementSteps: number;
  };
  readonly provenance?: ArenaExecutionProvenance;
}

export function createArenaRankingVerificationContext(
  input: ArenaRankingVerificationInput,
): ArenaRankingVerificationContext {
  const challengeId = identifier(input.challengeId, "Arena challenge ID");
  const rank = positiveInteger(input.rank, "Arena rank", 100_000);

  if (input.evidence === "illustrative") {
    if (input.provenance) throw new Error("Illustrative Arena rows cannot carry worker provenance");
    return Object.freeze({
      schema: "dnai.browser-evidence-selection.v1",
      source: "arena_ranking",
      classification: "illustrative_only",
      challengeId,
      challengeVersion: null,
      rank,
      submissionId: null,
      candidateCommitment: null,
      ladder: null,
      workerClaim: null,
    });
  }

  const challengeVersion = input.challengeVersion ? version(input.challengeVersion) : null;
  const submissionId = input.submissionId ? identifier(input.submissionId, "Arena submission ID") : null;
  const candidateCommitment = input.candidateCommitment
    ? sha256Digest(input.candidateCommitment, "Arena candidate commitment")
    : null;
  const ladder = ladderProjection(input.ladder);

  if (input.evidence === "none") {
    if (input.provenance && input.provenance.status !== "not_executed") {
      throw new Error("Projection-only Arena rows cannot carry worker execution provenance");
    }
    return Object.freeze({
      schema: "dnai.browser-evidence-selection.v1",
      source: "arena_ranking",
      classification: "projection_only_no_execution_evidence",
      challengeId,
      challengeVersion,
      rank,
      submissionId,
      candidateCommitment,
      ladder,
      workerClaim: null,
    });
  }

  if (!input.provenance || input.provenance.status !== "worker_reported") {
    throw new Error("Worker-reported Arena rows require bounded public provenance");
  }
  return Object.freeze({
    schema: "dnai.browser-evidence-selection.v1",
    source: "arena_ranking",
    classification: "worker_reported_qvl_binding_not_independently_verified",
    challengeId,
    challengeVersion,
    rank,
    submissionId,
    candidateCommitment,
    ladder,
    workerClaim: workerClaim(input.provenance),
  });
}

export function createComputeJobVerificationContext(
  job: Pick<
    ComputeJob,
    | "usage_receipt_hash"
    | "operation"
    | "result_policy"
    | "dispatch_status"
    | "provider_authoritative_settlement"
    | "raw_input_persisted"
    | "raw_output_persisted"
  >,
): ComputeReceiptHashVerificationContext {
  if (job.operation !== "inference" && job.operation !== "training") {
    throw new Error("Compute operation is outside the browser handoff contract");
  }
  if (job.result_policy !== "bounded_summary_receipt" && job.result_policy !== "score_band_hash") {
    throw new Error("Compute result policy is outside the browser handoff contract");
  }
  if (job.dispatch_status !== "not_dispatched") throw new Error("Compute dispatch status is outside the browser handoff contract");
  if (job.provider_authoritative_settlement !== false || job.raw_input_persisted !== false || job.raw_output_persisted !== false) {
    throw new Error("Compute job violates the bounded public receipt-hash invariants");
  }
  return Object.freeze({
    schema: "dnai.browser-evidence-selection.v1",
    source: "compute_receipt_hash",
    classification: "service_reported_hash_only_not_receipt",
    receiptSha256: sha256Digest(job.usage_receipt_hash, "Compute usage receipt hash"),
    operation: job.operation,
    resultPolicy: job.result_policy,
    dispatchStatus: "not_dispatched",
    providerAuthoritativeSettlement: false,
    rawInputPersisted: false,
    rawOutputPersisted: false,
  });
}

type DealResultFields = Pick<
  ChainDeal,
  | "id"
  | "state"
  | "scoreBand"
  | "resultHash"
  | "resultComposeHash"
  | "evaluatorPolicyCommitment"
  | "attestationEvidenceHash"
>;

export function createDealResultVerificationContext(
  deal: DealResultFields,
  options: Readonly<{ modeled: boolean; contractAddress?: string }>,
): DealResultVerificationContext {
  if (deal.state !== "Evaluated" && deal.state !== "Accepted" && deal.state !== "Rejected") {
    throw new Error("Deal result inspection requires a result-bearing room state");
  }
  if (!["Negligible", "Low", "Medium", "High", "Exceptional"].includes(deal.scoreBand)) {
    throw new Error("Deal score band is outside the bounded result contract");
  }

  const contractAddress = options.contractAddress
    ? publicAddress(options.contractAddress, "DiligenceRoom contract")
    : null;
  if (options.modeled && contractAddress) {
    throw new Error("An illustrative Deal Room result cannot claim a contract source");
  }
  if (!options.modeled && !contractAddress) {
    throw new Error("A contract-reported Deal Room result requires its public contract address");
  }

  return Object.freeze({
    schema: "dnai.browser-evidence-selection.v1",
    source: "deal_result",
    classification: options.modeled
      ? "illustrative_only"
      : "contract_reported_result_not_independently_verified",
    roomId: uint256Decimal(deal.id, "Deal room ID"),
    state: deal.state,
    scoreBand: deal.scoreBand,
    resultCommitment: hexDigest(deal.resultHash, "Deal result commitment"),
    composeBinding: hexDigest(deal.resultComposeHash, "Deal compose binding"),
    evaluatorPolicyCommitment: hexDigest(deal.evaluatorPolicyCommitment, "Deal evaluator policy"),
    attestationEvidenceCommitment: hexDigest(deal.attestationEvidenceHash, "Deal attestation evidence commitment"),
    chainId: 84532,
    contractAddress,
    independentlyVerifiedByBrowser: false,
    rawQuoteAvailable: false,
    intelCollateralVerifiedByBrowser: false,
  });
}
