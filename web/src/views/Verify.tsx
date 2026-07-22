import { createEffect, createMemo, createSignal, For, onMount, Show } from "solid-js";
import {
  AlertTriangle,
  Binary,
  Blocks,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleDashed,
  ClipboardCheck,
  CloudCog,
  Code2,
  ExternalLink,
  FileCheck2,
  Fingerprint,
  Link2,
  LockKeyhole,
  Network,
  RefreshCw,
  ScanLine,
  Sparkles,
  XCircle,
} from "lucide-solid";
import networkImage from "../../../outputs/wikigen-pitch-assets/attested-network.webp";
import { keccak256, type Address, type Hex } from "viem";
import { computeVaultDeployment, deployment, explorerAddress } from "../config";
import { EmailOracleReadinessPanel } from "../components/EmailOracleReadinessPanel";
import { publicClient, shortAddress } from "../lib/contract";
import type {
  VerificationContext,
  VerificationContextClassification,
} from "../lib/verificationContext";

type CheckState = "pass" | "pending" | "fail" | "modeled";
type EnvelopeState = "idle" | "loading" | "observed" | "incomplete" | "modeled" | "unsafe" | "error";

interface ContractRow {
  key: string;
  label: string;
  address?: Address;
  codeHash?: Hex;
  role: string;
}

interface Envelope {
  mode: string;
  quote: string;
  encryption_public_key: string;
  report_context: string;
  report_data: string;
  quote_report_data: string;
  app_id: string;
  compose_hash: string;
  os_image_hash: string;
  verified: boolean;
}

const ALLOWED_ENVELOPE_FIELDS = new Set([
  "mode",
  "quote",
  "encryption_public_key",
  "report_context",
  "report_data",
  "quote_report_data",
  "app_id",
  "compose_hash",
  "os_image_hash",
  "verified",
]);

const ENVELOPE_MAX_BYTES = 256 * 1024;
const QUOTE_MAX_CHARS = 240 * 1024;
const RECEIPT_MAX_BYTES = 64 * 1024;
const HEX_32 = /^0x[0-9a-fA-F]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isRawHex(value: string, hexCharacters: number): boolean {
  return value.length === hexCharacters && new RegExp(`^[0-9a-fA-F]{${hexCharacters}}$`).test(value);
}

function normalizedHex(value: string): string | undefined {
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  return raw.length > 0 && raw.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(raw) ? raw.toLowerCase() : undefined;
}

async function sha256Hex(value: string): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error("This browser cannot check the report-data binding");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function readBoundedText(response: Response, maximumBytes: number): Promise<string> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength) {
    const parsedLength = Number(declaredLength);
    if (Number.isFinite(parsedLength) && parsedLength > maximumBytes) {
      throw new Error("Envelope exceeded the 256 KiB public size limit");
    }
  }

  if (!response.body) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > maximumBytes) throw new Error("Envelope exceeded the 256 KiB public size limit");
    return text;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let bytesRead = 0;
  let text = "";
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bytesRead += chunk.value.byteLength;
      if (bytesRead > maximumBytes) {
        await reader.cancel();
        throw new Error("Envelope exceeded the 256 KiB public size limit");
      }
      text += decoder.decode(chunk.value, { stream: true });
    }
    return text + decoder.decode();
  } finally {
    reader.releaseLock();
  }
}

function receiptResultHash(record: Record<string, unknown>): unknown {
  if (record.result_hash !== undefined) return record.result_hash;
  return isRecord(record.output) ? record.output.result_hash : undefined;
}

function assertBoundedReceiptShape(record: Record<string, unknown>): void {
  if (typeof record.request_id !== "string" || record.request_id.length < 1 || record.request_id.length > 160 || /[\u0000-\u001f]/.test(record.request_id)) {
    throw new Error("request_id must be a bounded printable string");
  }
  if (typeof record.compose_hash !== "string" || !HEX_32.test(record.compose_hash)) {
    throw new Error("compose_hash must be a 0x-prefixed bytes32 value");
  }
  const resultHash = receiptResultHash(record);
  if (typeof resultHash !== "string" || !HEX_32.test(resultHash)) {
    throw new Error("result_hash must be a 0x-prefixed bytes32 value at the root or inside output");
  }
  if (record.result_hash !== undefined && isRecord(record.output) && record.output.result_hash !== undefined && record.result_hash !== record.output.result_hash) {
    throw new Error("Conflicting root and output result_hash values");
  }
  if (typeof record.signature !== "string" || record.signature.length < 1 || record.signature.length > 4096) {
    throw new Error("signature must be a bounded string");
  }
}

const LEVELS = [
  ["01", "Illustrative receipt", "A local demo record with modeled fields. No cryptographic or hardware claim."],
  ["02", "Application envelope", "A bounded response from the service with the declared encryption key and report binding."],
  ["03", "Quote parsed", "The TDX quote envelope is structurally decoded and report data can be compared."],
  ["04", "Quote verified", "The hardware quote chain and collateral are cryptographically validated."],
  ["05", "Policy matched", "Measurements, image digest, compose hash, app identity, and signer equal the approved manifest."],
  ["06", "Receipt verified", "A result is bound end-to-end to request, policy, execution, output, and settlement."],
];

const SELECTED_CONTEXT_LABELS: Record<VerificationContextClassification, string> = {
  illustrative_only: "Illustrative · no execution",
  projection_only_no_execution_evidence: "Projection only · no execution evidence",
  worker_reported_qvl_binding_not_independently_verified: "Worker-reported · not independently verified",
  contract_reported_result_not_independently_verified: "Contract-reported · not independently verified",
  service_reported_hash_only_not_receipt: "Hash only · receipt body absent",
};

interface SelectedEvidenceFact {
  label: string;
  value: string;
  format?: "hash" | "address";
}

interface SelectedEvidencePresentation {
  title: string;
  subtitle: string;
  caveat: string;
  facts: readonly SelectedEvidenceFact[];
}

function selectedEvidencePresentation(context: VerificationContext): SelectedEvidencePresentation {
  if (context.source === "deal_result") {
    const facts: SelectedEvidenceFact[] = [
      { label: "Room ID", value: context.roomId },
      { label: "Room state", value: context.state },
      { label: "Bounded score band", value: context.scoreBand },
      { label: "Result commitment", value: context.resultCommitment, format: "hash" },
      { label: "Compose binding", value: context.composeBinding, format: "hash" },
      { label: "Evaluator policy", value: context.evaluatorPolicyCommitment, format: "hash" },
      { label: "Attestation evidence commitment", value: context.attestationEvidenceCommitment, format: "hash" },
      { label: "Chain ID", value: context.chainId.toString() },
      { label: "DiligenceRoom", value: context.contractAddress ?? "Modeled preview · no contract source", format: context.contractAddress ? "address" : undefined },
      { label: "Independently verified by browser", value: "false" },
      { label: "Raw quote available", value: "false" },
      { label: "Intel collateral verified by browser", value: "false" },
    ];

    if (context.classification === "illustrative_only") {
      return {
        title: "Illustrative Deal Room result",
        subtitle: "Designed sample · no chain read, worker execution, or attestation verification",
        caveat: "These are modeled display values. No contract reported them, no evaluator ran, and no raw TDX quote, QVL verdict, Intel collateral, result signature, or release-policy match exists for this sample.",
        facts,
      };
    }
    return {
      title: "Deal Room result projection",
      subtitle: "Contract-reported public fields · independent browser verification not performed",
      caveat: "The Deal Room read path reports these public result and attestation commitments. This browser has not authenticated the result-verifier or QVL signatures, received or checked a raw TDX quote, verified Intel collateral, or matched the evidence to the approved release policy.",
      facts,
    };
  }

  if (context.source === "compute_receipt_hash") {
    return {
      title: "Compute usage-receipt reference",
      subtitle: "Authenticated service selection · project and job identity intentionally omitted",
      caveat: "The authenticated service supplied a SHA-256 reference, not a receipt body. This browser cannot inspect receipt shape or verify its signer, metering source, provider execution, or settlement from that hash alone.",
      facts: [
        { label: "Usage receipt hash", value: context.receiptSha256, format: "hash" },
        { label: "Operation", value: context.operation },
        { label: "Result policy", value: context.resultPolicy.replaceAll("_", " ") },
        { label: "Dispatch status", value: context.dispatchStatus.replaceAll("_", " ") },
        { label: "Provider-authoritative settlement", value: "false" },
        { label: "Raw input persisted", value: "false" },
        { label: "Raw output persisted", value: "false" },
      ],
    };
  }

  const facts: SelectedEvidenceFact[] = [
    { label: "Challenge ID", value: context.challengeId },
    { label: "Challenge version", value: context.challengeVersion ?? "No released version" },
    { label: "Public rank", value: context.rank.toLocaleString("en-US") },
  ];
  if (context.submissionId) facts.push({ label: "Submission ID", value: context.submissionId });
  if (context.candidateCommitment) facts.push({ label: "Candidate commitment", value: context.candidateCommitment, format: "hash" });
  if (context.ladder) {
    facts.push(
      { label: "Ladder release", value: `${context.ladder.stepIndex}/${context.ladder.denominator}` },
      { label: "Improvement steps", value: context.ladder.improvementSteps.toLocaleString("en-US") },
    );
  }
  if (context.workerClaim) {
    facts.push(
      { label: "Worker outcome", value: context.workerClaim.outcome },
      { label: "Runtime policy", value: context.workerClaim.runtimePolicyCommitment, format: "hash" },
      { label: "Challenge manifest", value: context.workerClaim.challengeManifestHash, format: "hash" },
      { label: "Compose hash", value: context.workerClaim.composeHash, format: "hash" },
      { label: "OS image hash", value: context.workerClaim.osImageHash, format: "hash" },
      { label: "Quote digest", value: context.workerClaim.quoteSha256, format: "hash" },
      { label: "QVL signer claim", value: context.workerClaim.verifierAddress, format: "address" },
      { label: "Verdict digest", value: context.workerClaim.verdictDigest, format: "hash" },
      { label: "TEE signer claim", value: context.workerClaim.teeSignerAddress, format: "address" },
      { label: "Challenge registry", value: context.workerClaim.registryAddress, format: "address" },
      { label: "Chain ID", value: context.workerClaim.chainId.toString() },
    );
  }

  if (context.classification === "illustrative_only") {
    return {
      title: "Illustrative Arena ranking",
      subtitle: "Designed sample · no released submission identity or provenance",
      caveat: "No program ran, no reward exists, and no execution, TDX, or QVL evidence is attached to this modeled row.",
      facts,
    };
  }
  if (context.classification === "projection_only_no_execution_evidence") {
    return {
      title: "Arena ranking projection",
      subtitle: "Bounded public row · no execution provenance attached",
      caveat: "This service-projected ranking has no row-level execution evidence. It must not be read as proof that a program ran, a quote was parsed, or a reward was earned.",
      facts,
    };
  }
  return {
    title: "Arena worker-reported provenance",
    subtitle: "Bounded public commitments · independent browser verification not performed",
    caveat: "The service reports a QVL-bound worker record. This browser has not received the raw quote, verified Intel collateral, authenticated the verdict signature, or matched the approved release policy independently.",
    facts,
  };
}

const EXAMPLE_RECEIPT = JSON.stringify({
  kind: "modeled-receipt",
  request_id: "req_demo_01",
  outcome: "cleared",
  result_policy: "ladder-v1",
  output: { band: "HIGH", result_hash: `0x${"ab".repeat(32)}` },
  compose_hash: `0x${"cd".repeat(32)}`,
  signature: "modeled-receipt:not-a-hardware-signature",
}, null, 2);

function LayerState(props: { state: CheckState }) {
  return (
    <span class={`layer-state ${props.state}`}>
      {props.state === "pass" ? <CheckCircle2 size={14} /> : props.state === "fail" ? <XCircle size={14} /> : <CircleDashed size={14} />}
      {props.state === "pass" ? "observed" : props.state}
    </span>
  );
}

export function Verify(props: {
  selectedEvidence?: VerificationContext;
  clearSelectedEvidence?: () => void;
} = {}) {
  const [envelope, setEnvelope] = createSignal<Envelope>();
  const [envelopeState, setEnvelopeState] = createSignal<EnvelopeState>("idle");
  const [envelopeMessage, setEnvelopeMessage] = createSignal("Fresh CVM endpoint is not configured.");
  const [contractStates, setContractStates] = createSignal<Record<string, CheckState>>({});
  const [contractBusy, setContractBusy] = createSignal(false);
  const [contractBlockNumber, setContractBlockNumber] = createSignal<bigint>();
  const [receiptText, setReceiptText] = createSignal(EXAMPLE_RECEIPT);
  const [receiptResult, setReceiptResult] = createSignal<{ state: CheckState; title: string; detail: string }>();
  let selectedEvidenceRegion: HTMLElement | undefined;

  const selectedPresentation = createMemo(() => (
    props.selectedEvidence ? selectedEvidencePresentation(props.selectedEvidence) : undefined
  ));

  createEffect(() => {
    if (!props.selectedEvidence) return;
    queueMicrotask(() => selectedEvidenceRegion?.focus({ preventScroll: true }));
  });

  function clearSelectedEvidence(): void {
    props.clearSelectedEvidence?.();
    queueMicrotask(() => document.getElementById("verification-ladder-title")?.focus({ preventScroll: true }));
  }

  const contractRows = createMemo<readonly ContractRow[]>(() => [
    { key: "diligence", label: "DiligenceRoom", address: deployment.contractAddress, codeHash: deployment.contractCodeHash, role: "Escrow + bounded result settlement" },
    { key: "challenge", label: "ChallengeRegistry", address: deployment.challengeRegistryAddress, codeHash: deployment.challengeRegistryCodeHash, role: "Versioned public challenge commitments" },
    { key: "compute-vault", label: "ComputeCreditVault", address: computeVaultDeployment.address, codeHash: computeVaultDeployment.codeHash, role: "Exact-asset capacity + bounded job authorization" },
    ...(computeVaultDeployment.token ? [{ key: "compute-asset", label: `${computeVaultDeployment.token.symbol} capacity asset`, address: computeVaultDeployment.token.address, codeHash: computeVaultDeployment.token.codeHash, role: "Single release-pinned ERC20 runtime" }] : []),
    { key: "encumbrance", label: "TinkerAccountEncumbrance", address: deployment.encumbranceAddress, codeHash: deployment.encumbranceCodeHash, role: "Delegated-operation policy authorization" },
    { key: "royalty", label: "RoyaltyDistributor", address: deployment.royaltyDistributorAddress, codeHash: deployment.royaltyDistributorCodeHash, role: "Pull-payment royalty accounting" },
    { key: "email-oracle-auth", label: "EmailOracleAuth", address: deployment.emailOracleAuthAddress, codeHash: deployment.emailOracleAuthCodeHash, role: "Release-pinned email-oracle device authorization" },
    { key: "execution-policy-anchor", label: "ExecutionPolicyAnchor", address: deployment.executionPolicyAnchorAddress, codeHash: deployment.executionPolicyAnchorCodeHash, role: "Monotonic rollback witness for bounded policy decisions" },
  ]);

  const configuredContractCount = createMemo(() => contractRows().filter((row) => Boolean(row.address)).length);
  const observedContractCount = createMemo(() => contractRows().filter((row) => contractStates()[row.key] === "pass").length);
  const receiptByteLength = createMemo(() => new TextEncoder().encode(receiptText()).byteLength);
  const observationSummary = createMemo(() => {
    const contracts = observedContractCount();
    const endpointObserved = ["observed", "incomplete", "modeled"].includes(envelopeState());
    if (contracts > 0 && endpointObserved) return { title: "Reachability observed", detail: `${contracts} configured contract${contracts === 1 ? " has" : "s have"} bytecode, and the configured endpoint returned a bounded envelope. Neither observation verifies deployment policy.` };
    if (contracts > 0) return { title: "Contract runtime observed", detail: `${contracts} configured address${contracts === 1 ? " has" : "es have"} bytecode; every row carrying a release code-hash pin also matched it. The confidential-runtime envelope has not been observed.` };
    if (endpointObserved) return { title: "Endpoint envelope observed", detail: "The configured endpoint returned an allowlisted envelope. No configured contract bytecode has been observed." };
    if (configuredContractCount() > 0 || deployment.delegateUrl) return { title: "Configuration present", detail: "Addresses or an endpoint are configured, but this browser has not yet observed the corresponding evidence." };
    return { title: "No fresh deployment config", detail: "This build intentionally does not inherit the previous operator's contracts or CVM." };
  });

  const inspectContracts = async () => {
    if (contractBusy()) return;
    setContractBusy(true);
    setContractBlockNumber(undefined);
    const next: Record<string, CheckState> = {};
    try {
      const configuredRows = contractRows().filter((row) => Boolean(row.address));
      if (configuredRows.length === 0) {
        for (const row of contractRows()) next[row.key] = "pending";
        setContractStates(next);
        return;
      }
      const blockNumber = await publicClient.getBlockNumber();
      await Promise.all(contractRows().map(async (row) => {
        if (!row.address) {
          next[row.key] = "pending";
          return;
        }
        try {
          const code = await publicClient.getBytecode({ address: row.address, blockNumber });
          const codeHashMatches = !row.codeHash
            || (code && code !== "0x" && keccak256(code).toLowerCase() === row.codeHash.toLowerCase());
          next[row.key] = code && code !== "0x" && codeHashMatches ? "pass" : "fail";
        } catch {
          next[row.key] = "fail";
        }
      }));
      setContractStates(next);
      setContractBlockNumber(blockNumber);
    } finally {
      setContractBusy(false);
    }
  };

  const inspectEnvelope = async () => {
    if (!deployment.delegateUrl) {
      setEnvelopeState("idle");
      setEnvelopeMessage("Fresh CVM endpoint is not configured.");
      return;
    }
    setEnvelopeState("loading");
    try {
      const url = `${deployment.delegateUrl.replace(/\/$/, "")}/attestation?context=ingress`;
      const response = await fetch(url, { cache: "no-store", credentials: "omit", signal: AbortSignal.timeout(8000) });
      if (!response.ok) throw new Error(`Endpoint returned ${response.status}`);
      if (!response.headers.get("content-type")?.toLowerCase().includes("application/json")) throw new Error("Endpoint did not return application/json");
      const body = await readBoundedText(response, ENVELOPE_MAX_BYTES);
      const value: unknown = JSON.parse(body);
      if (!isRecord(value)) throw new Error("Envelope is not an object");
      const record = value;
      const unexpected = Object.keys(record).filter((key) => !ALLOWED_ENVELOPE_FIELDS.has(key));
      if (unexpected.length) {
        setEnvelope(undefined);
        setEnvelopeState("unsafe");
        setEnvelopeMessage(`Response rejected: ${unexpected.length} undeclared field${unexpected.length === 1 ? "" : "s"}. No values were rendered.`);
        return;
      }
      const candidate = record as unknown as Envelope;
      const strings = [candidate.mode, candidate.quote, candidate.encryption_public_key, candidate.report_context, candidate.report_data, candidate.quote_report_data, candidate.app_id, candidate.compose_hash, candidate.os_image_hash];
      if (strings.some((item) => typeof item !== "string") || typeof candidate.verified !== "boolean") {
        throw new Error("Required bounded fields are missing");
      }
      if (!new Set(["local", "tdx"]).has(candidate.mode)) throw new Error("Envelope mode is not local or tdx");
      if (candidate.report_context !== "ingress") throw new Error("Envelope context is not ingress");
      if (candidate.verified !== false) throw new Error("A quote producer cannot mark its own evidence independently verified");
      if (!isRawHex(candidate.encryption_public_key, 64)) throw new Error("Encryption public key must be exactly 32 raw hex bytes");
      if (!isRawHex(candidate.report_data, 64)) throw new Error("Report data must be exactly 32 raw hex bytes");
      if (candidate.quote.length > QUOTE_MAX_CHARS || strings.slice(6).some((item) => item.length > 256)) {
        throw new Error("Envelope contains an oversized declared field");
      }

      const quote = candidate.quote ? normalizedHex(candidate.quote) : "";
      if (candidate.quote && !quote) throw new Error("Quote must be an even-length hex value");
      const quoteReportData = candidate.quote_report_data ? normalizedHex(candidate.quote_report_data) : "";
      if (candidate.quote_report_data && (!quoteReportData || ![64, 128].includes(quoteReportData.length))) {
        throw new Error("quote_report_data must contain exactly 32 or 64 bytes");
      }
      if (quoteReportData && quoteReportData.slice(0, 64) !== candidate.report_data.toLowerCase()) {
        throw new Error("quote_report_data does not match report_data");
      }
      if (quoteReportData?.length === 128 && quoteReportData.slice(64) !== "0".repeat(64)) {
        throw new Error("The upper half of 64-byte quote_report_data must be zero");
      }

      const canonicalBinding = JSON.stringify({
        context: candidate.report_context,
        encryption_public_key: candidate.encryption_public_key.toLowerCase(),
        service: "tinker-delegate",
      });
      const expectedReportData = await sha256Hex(canonicalBinding);
      if (candidate.report_data.toLowerCase() !== expectedReportData) {
        throw new Error("Report data is not bound to this context and encryption key");
      }

      setEnvelope(candidate);
      if (candidate.mode === "local") {
        if (candidate.quote || candidate.quote_report_data) throw new Error("Local mode must not carry TDX evidence");
        setEnvelopeState("modeled");
        setEnvelopeMessage("A context-and-key-bound local envelope was observed. It is simulator evidence, not Intel TDX evidence.");
      } else if (candidate.quote && candidate.quote_report_data && candidate.app_id && candidate.compose_hash && candidate.os_image_hash) {
        setEnvelopeState("observed");
        setEnvelopeMessage("Bounded TDX evidence fields were observed and their report-data binding matches. Quote signature, collateral, and policy remain independently unverified.");
      } else {
        setEnvelopeState("incomplete");
        setEnvelopeMessage("A bounded tdx-mode envelope responded, but quote or identity evidence is incomplete. Do not encrypt or execute against it.");
      }
    } catch (error) {
      setEnvelope(undefined);
      setEnvelopeState("error");
      setEnvelopeMessage(error instanceof Error ? error.message : "Could not inspect the endpoint");
    }
  };

  const inspectReceipt = () => {
    try {
      if (receiptByteLength() === 0) throw new Error("Receipt JSON is empty");
      if (receiptByteLength() > RECEIPT_MAX_BYTES) throw new Error("Receipt exceeds the 64 KiB local inspection limit");
      const parsed: unknown = JSON.parse(receiptText());
      if (!isRecord(parsed)) throw new Error("Receipt must be a JSON object");
      const record = parsed;
      assertBoundedReceiptShape(record);
      const modeledKind = record.kind === "modeled-receipt";
      const modeledSignature = typeof record.signature === "string" && record.signature.startsWith("modeled-receipt:");
      if (modeledKind !== modeledSignature) throw new Error("Modeled receipt markers disagree");
      if (modeledKind) {
        setReceiptResult({ state: "modeled", title: "Modeled receipt recognized", detail: "The shape is useful for interface testing, but it is explicitly not a TDX quote or production evaluator signature." });
        return;
      }
      setReceiptResult({ state: "pending", title: "Bounded shape only · unverified", detail: "The request, result, compose, and signature fields are structurally bounded. This browser has not canonicalized the payload, recovered a trusted signer, checked a quote, or matched deployment policy." });
    } catch (error) {
      setReceiptResult({ state: "fail", title: "Invalid receipt", detail: error instanceof Error ? error.message : "The payload could not be parsed." });
    }
  };

  onMount(() => {
    void inspectContracts();
    void inspectEnvelope();
  });

  const ladderState = (index: number): CheckState => {
    if (index === 0) return "modeled";
    if (index !== 1) return "pending";
    if (envelopeState() === "modeled") return "modeled";
    return envelopeState() === "observed" || envelopeState() === "incomplete" ? "pass" : "pending";
  };

  const envelopeHeading = (): string => {
    switch (envelopeState()) {
      case "observed": return "Bounded TDX evidence observed";
      case "incomplete": return "Incomplete tdx-mode envelope";
      case "modeled": return "Local modeled envelope observed";
      case "unsafe": return "Undeclared response rejected";
      case "error": return "Endpoint inspection failed";
      case "loading": return "Inspecting bounded endpoint…";
      default: return "Fresh endpoint not observed";
    }
  };

  return (
    <div class="product-page verify-page">
      <section class="verify-hero">
        <img src={networkImage} alt="" aria-hidden="true" />
        <div class="verify-hero-mask" />
        <div class="page-wrap verify-hero-content">
          <div>
            <p class="overline">Trust center · verify, don't infer</p>
            <h1>Follow every claim to evidence.</h1>
            <p>Wikigen treats attestation as a layered proof, not a green badge. This browser observes configured contract bytecode, checks a bounded application-envelope binding, and classifies receipt shape. It does not perform independent Intel collateral, QVL-signature, or release-policy verification.</p>
          </div>
          <div class="verify-summary-card" role="status" aria-live="polite" aria-atomic="true">
            <div><Fingerprint size={22} /><span><small>BROWSER-OBSERVED LEVEL</small><strong>{observationSummary().title}</strong></span></div>
            <p>{observationSummary().detail}</p>
          </div>
        </div>
      </section>

      <div class="page-wrap verify-body">
        <Show when={selectedPresentation()} keyed>
          {(presentation) => (
            <section
              ref={(element) => { selectedEvidenceRegion = element; }}
              class={`selected-evidence-context ${props.selectedEvidence?.classification ?? ""}`}
              role="region"
              aria-labelledby="selected-evidence-title"
              tabindex="-1"
            >
              <div class="selected-evidence-head">
                <div>
                  <p class="overline">IN-MEMORY PUBLIC PROJECTION</p>
                  <h2 id="selected-evidence-title">{presentation.title}</h2>
                  <p>{presentation.subtitle}</p>
                </div>
                <div class="selected-evidence-actions">
                  <span class={`selected-evidence-classification ${props.selectedEvidence?.classification ?? ""}`}><Fingerprint size={14} />{props.selectedEvidence ? SELECTED_CONTEXT_LABELS[props.selectedEvidence.classification] : ""}</span>
                  <Show when={props.clearSelectedEvidence}><button class="ghost-button" type="button" onClick={clearSelectedEvidence}><XCircle size={14} /> Clear selected context</button></Show>
                </div>
              </div>
              <div class="selected-evidence-facts">
                <For each={presentation.facts}>{(item) => <div><small>{item.label}</small>{item.format === "hash" || item.format === "address" ? <code>{item.value}</code> : <strong>{item.value}</strong>}</div>}</For>
              </div>
              <div class="selected-evidence-caveat"><LockKeyhole size={16} /><span><strong>Evidence boundary</strong>{presentation.caveat} Selecting this row never advances the six-level ladder or seeds the receipt editor.</span></div>
              <p class="selected-evidence-lifetime">In-memory selection · cleared on reload/navigation. Browser Back returns to the source route.</p>
            </section>
          )}
        </Show>

        <section class="verification-ladder">
          <div class="section-heading split-heading compact-heading"><div><p class="overline">Evidence maturity</p><h2 id="verification-ladder-title" tabindex="-1">Six levels—not one boolean.</h2></div><p>Each level adds a distinct claim. A result may proceed only to the highest independently checked level.</p></div>
          <div class="ladder-track">
            <For each={LEVELS}>{(level, index) => <article class={ladderState(index()) !== "pending" ? "active" : ""}><span>{level[0]}</span><div><h3>{level[1]}</h3><p>{level[2]}</p></div><LayerState state={ladderState(index())} /></article>}</For>
          </div>
        </section>

        <section class="verification-grid">
          <article class="verification-panel contract-verifier">
            <div class="panel-head"><div><p class="overline">Layer · settlement</p><h2>Base Sepolia bytecode</h2></div><button class="icon-button" type="button" aria-label="Refresh contract bytecode checks" aria-controls="contract-observation-status" aria-busy={contractBusy()} disabled={contractBusy()} onClick={() => void inspectContracts()}><RefreshCw class={contractBusy() ? "spin" : ""} size={16} /></button></div>
            <p id="contract-observation-status" class="sr-only" role="status" aria-live="polite">{contractBusy() ? "Inspecting configured contract bytecode." : `${observedContractCount()} of ${configuredContractCount()} configured contract addresses have matching observed bytecode.`}</p>
            <For each={contractRows()}>{(row) => <div class="contract-check-row"><span class="contract-symbol"><Blocks size={16} /></span><div><strong>{row.label}</strong><small>{row.role}</small><Show when={row.address} fallback={<span class="contract-unconfigured">Address not configured for this release</span>}><a href={explorerAddress(row.address ?? "")} target="_blank" rel="noreferrer" aria-label={`View ${row.label} at ${row.address} on BaseScan`}><code>{shortAddress(row.address ?? "", 7)}</code><ExternalLink size={12} /></a></Show></div><LayerState state={contractStates()[row.key] ?? "pending"} /></div>}</For>
            <p class="panel-footnote"><Network size={13} /> Bytecode presence—and an exact runtime-hash match wherever this release carries a pin—is necessary, not sufficient: source verification, constructor inputs, roles, approved compose hash, and signer ownership also need review.<Show when={contractBlockNumber() !== undefined}> All bytecode observations above were pinned to Base Sepolia block <code>{contractBlockNumber()?.toString()}</code>.</Show></p>
          </article>

          <article class="verification-panel envelope-verifier">
            <div class="panel-head"><div><p class="overline">Layer · confidential runtime</p><h2>Bounded CVM envelope</h2></div><button class="icon-button" type="button" aria-label="Refresh CVM envelope" aria-controls="envelope-observation-status" aria-busy={envelopeState() === "loading"} disabled={envelopeState() === "loading"} onClick={() => void inspectEnvelope()}><RefreshCw class={envelopeState() === "loading" ? "spin" : ""} size={16} /></button></div>
            <div id="envelope-observation-status" class={`envelope-status ${envelopeState()}`} role="status" aria-live="polite" aria-atomic="true">
              {envelopeState() === "unsafe" || envelopeState() === "error" ? <AlertTriangle size={20} /> : <CloudCog size={20} />}
              <div><strong>{envelopeHeading()}</strong><span>{envelopeMessage()}</span></div>
            </div>
            <Show when={envelope()}>{(value) => <div class="envelope-facts"><div><span>Mode</span><strong>{value().mode}</strong></div><div><span>App ID</span><code>{shortAddress(value().app_id || "unavailable", 7)}</code></div><div><span>Compose</span><code>{shortAddress(value().compose_hash || "unavailable", 7)}</code></div><div><span>OS image</span><code>{shortAddress(value().os_image_hash || "unavailable", 7)}</code></div><div><span>Encryption key</span><code>{shortAddress(value().encryption_public_key, 7)}</code></div><div><span>Producer verdict</span><strong>{value().verified === false ? "Not independently verified" : "Rejected"}</strong></div></div>}</Show>
            <p class="panel-footnote"><LockKeyhole size={13} /> The UI rejects undeclared fields, verifies the context-to-key report-data binding, and never renders compose YAML, container environment, system info, or runtime secrets. It does not verify Intel collateral.</p>
          </article>
        </section>

        <EmailOracleReadinessPanel />

        <section class="receipt-workbench">
          <div class="receipt-workbench-copy">
            <p class="overline">Layer · result provenance</p>
            <h2>Receipt inspection workbench</h2>
            <p>Paste a bounded receipt to classify its evidence level. This browser checks size, types, nested or root result-hash placement, and modeled markers. It does not perform signer, quote, or policy verification.</p>
            <ul><li><Check size={14} /> Rejects malformed JSON</li><li><Check size={14} /> Recognizes modeled receipts</li><li><Check size={14} /> Never upgrades shape to hardware proof</li></ul>
          </div>
          <div class="receipt-editor">
            <div class="receipt-editor-head"><span><Code2 size={15} /> receipt.json</span><span>LOCAL INSPECTION</span></div>
            <textarea value={receiptText()} maxlength={RECEIPT_MAX_BYTES} onInput={(event) => { setReceiptText(event.currentTarget.value); setReceiptResult(undefined); }} spellcheck={false} aria-label="Receipt JSON" aria-describedby="receipt-size-note" aria-invalid={receiptByteLength() > RECEIPT_MAX_BYTES} />
            <div id="receipt-size-note" class={`receipt-size ${receiptByteLength() > RECEIPT_MAX_BYTES ? "over" : ""}`} aria-live="polite">{receiptByteLength().toLocaleString()} / {RECEIPT_MAX_BYTES.toLocaleString()} bytes · inspected locally</div>
            <button class="primary-button full" type="button" disabled={receiptByteLength() === 0 || receiptByteLength() > RECEIPT_MAX_BYTES} onClick={inspectReceipt}><ScanLine size={16} /> Inspect bounded shape</button>
            <Show when={receiptResult()}>{(result) => <div class={`receipt-result ${result().state}`} role="status"><ClipboardCheck size={18} /><div><strong>{result().title}</strong><span>{result().detail}</span></div></div>}</Show>
          </div>
        </section>

        <section class="manifest-chain">
          <div><p class="overline">Reproducibility chain</p><h2>From source to result.</h2><p>Each arrow must be pinned and reviewable. A match at the end cannot repair an untrusted link earlier in the chain.</p></div>
          <div class="manifest-flow" role="region" aria-label="Source-to-receipt reproducibility chain" tabindex="0">
            <span><Code2 size={16} /><strong>Git SHA</strong><small>{deployment.verificationChainReleaseSha?.slice(0, 12) ?? "unconfigured · modeled"}</small></span><ChevronRight size={16} /><span><Binary size={16} /><strong>Image digest</strong><small>{shortAddress(deployment.imageDigest || "pending", 6)}</small></span><ChevronRight size={16} /><span><FileCheck2 size={16} /><strong>Compose hash</strong><small>{shortAddress(deployment.composeHash || "pending", 6)}</small></span><ChevronRight size={16} /><span><Fingerprint size={16} /><strong>TDX quote</strong><small>independent verification</small></span><ChevronRight size={16} /><span><Link2 size={16} /><strong>Receipt</strong><small>request → result</small></span>
          </div>
        </section>

        <div class="environment-banner warning"><Sparkles size={16} /><div><strong>No inherited trust</strong><span>The previous operator's deployment is intentionally absent from this interface. A fresh manifest is eligible for use only after project-owned keys, contracts, CVMs, measurements, and end-to-end checks agree.</span></div></div>
      </div>
    </div>
  );
}
