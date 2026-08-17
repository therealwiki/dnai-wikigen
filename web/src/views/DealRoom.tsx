import { createEffect, createMemo, createSignal, For, onMount, Show } from "solid-js";
import {
  ArrowRight,
  CheckCircle2,
  CircleDollarSign,
  Clock3,
  Download,
  ExternalLink,
  FileKey,
  FileUp,
  Filter,
  HandCoins,
  Hash,
  LoaderCircle,
  LockKeyhole,
  Plus,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
  WalletCards,
  XCircle,
} from "lucide-solid";
import {
  getAddress,
  formatUnits,
  keccak256,
  parseEther,
  parseUnits,
  zeroAddress,
  type Address,
  type Hex,
} from "viem";
import { baseSepolia } from "viem/chains";
import { BASE_SEPOLIA_USDC_ADDRESS, computeVaultDeployment, deployment, explorerTx } from "../config";
import {
  assertDealCreationIntentContext,
  createDealCreationIntent,
  createDealCreationRecovery,
  DEAL_CREATION_CONFIRMATION_DEPTH,
  DEAL_CREATION_RECOVERY_STORAGE_KEY,
  decodeDealCreationRecovery,
  diligenceRoomAbi,
  encodeDealCreationRecovery,
  formatEth,
  isZeroAddress,
  loadDealById,
  loadDiligenceWritePolicySnapshot,
  loadDeals,
  mergeDealPages,
  publicClient,
  reconcileDealCreation,
  shortAddress,
  type ChainDeal,
  type DealCreationReconciliation,
  type DealCreationRecovery,
  type DealPageCursor,
  type DealSnapshot,
  type DealState,
  type ExactDealLookup,
  walletRequestWasExplicitlyRejected,
} from "../lib/contract";
import { wallet } from "../lib/wallet";
import {
  ARTIFACT_COMMITMENT_SCHEME,
  MAX_ARTIFACT_BYTES,
  createArtifactRecoveryReceipt,
  parseArtifactRecoveryReceipt,
  uploadEncryptedArtifact,
  type ArtifactRecoveryReceipt,
} from "../lib/artifact";
import {
  assertWalletMutationContext,
  promptAfterFreshPolicy,
} from "../lib/writeAuthorization";
import {
  DILIGENCE_RECIPES,
  DILIGENCE_RECIPE_COPY,
  type DiligenceEvaluatorPolicyDescriptor,
} from "../lib/diligencePolicies";
import {
  DealRoomOperationLock,
  dealRoomDraftMutationIsAllowed,
  runDealRoomOperation,
  type DealRoomOperationLease,
} from "../lib/dealRoomOperation";
import {
  createDealResultVerificationContext,
  type VerificationContext,
} from "../lib/verificationContext";

type DealFilter = "all" | "open" | "mine" | "settled";
type TxState = { kind: "idle" | "wallet" | "chain" | "success" | "error"; label: string; hash?: Hex };
type DealListFailure = "restart" | "more" | undefined;
type DealCreationResolution =
  | DealCreationReconciliation
  | Readonly<{
    status: "not_broadcast";
    reason: string;
    observedThroughBlock: bigint;
    transactionHash?: undefined;
  }>;
type StoredDealCreationRecovery = Readonly<{
  recovery?: DealCreationRecovery;
  error?: string;
  restored: boolean;
}>;
type ArtifactUploadRecovery = Readonly<{
  dealId: string;
  file: File;
  receipt: ArtifactRecoveryReceipt;
  receiptName: string;
  message: string;
}>;
export type DealIngressPhase =
  | "idle"
  | "authorizing"
  | "encrypting"
  | "retrying"
  | "accepted"
  | "failed_preflight"
  | "delivery_uncertain";
type DealIngressLifecycle = Readonly<{
  phase: DealIngressPhase;
  ciphertextReceipt?: string;
}>;
export type DealLifecycleTone = "complete" | "current" | "pending" | "unobserved" | "failed" | "expired";
export type DealLifecycleStep = Readonly<{
  key: "ciphertext" | "queue" | "policy" | "evaluation" | "result" | "resolution";
  label: string;
  detail: string;
  tone: DealLifecycleTone;
}>;
export type DealLifecycleProjection = Readonly<{
  headline: string;
  explanation: string;
  steps: readonly DealLifecycleStep[];
}>;

function lifecycleSteps(...steps: DealLifecycleStep[]): readonly DealLifecycleStep[] {
  return Object.freeze(steps);
}
type ContractWritePolicy = {
  bytecodeObserved: true;
  inspectedBlock: bigint;
  productionRelease: true;
  developer: Address;
  initialDeveloper: Address;
  releaseGovernanceController: Address;
  pendingDeveloper: typeof zeroAddress;
  pendingDeveloperActivatesAt: 0n;
  resultVerifier: Address;
  resultVerifierFrozen: true;
  attestationVerifier: Address;
  attestationReleasePolicyHash: Hex;
  attestationBindingFrozen: true;
  composeApprovalRequired: true;
  teeIdentityApprovalRequired: true;
  approvalRequirementsFrozen: true;
  composeAdditionsFrozen: true;
  teeIdentityAdditionsFrozen: true;
  feeBpsFrozen: true;
  computeSettlementPolicyEnabled: true;
  approvedComposeCount: 1n;
  approvedTeeIdentityCount: 1n;
  pendingComposeCount: 0n;
  pendingTeeIdentityCount: 0n;
  approvedEvaluatorPolicyCount: 3n;
  pendingEvaluatorPolicyCount: 0n;
  evaluatorPolicySetFrozen: true;
  evaluatorPolicySetRoot: Hex;
  evaluatorPolicies: readonly [Hex, Hex, Hex];
  teeComposeHash: Hex;
  composeApproved: true;
};

type AuthorizedWrite = {
  client: NonNullable<ReturnType<typeof wallet.client>>;
  account: Address;
  contract: Address;
  policy: ContractWritePolicy;
};

type AuthorizeWrite = (prompt: (authorized: AuthorizedWrite) => Promise<Hex>) => Promise<Hex>;
type TransactHooks = Readonly<{
  onBroadcast?: (hash: Hex) => void;
  onFailure?: (cause: unknown, hash: Hex | undefined, walletPromptOpened: boolean) => void;
}>;

function readStoredDealCreationRecovery(): StoredDealCreationRecovery {
  let serialized: string | null;
  try {
    serialized = window.localStorage.getItem(DEAL_CREATION_RECOVERY_STORAGE_KEY);
  } catch (cause) {
    return Object.freeze({
      restored: false,
      error: cause instanceof Error ? cause.message : "Browser recovery storage is unavailable",
    });
  }
  if (!serialized) return Object.freeze({ restored: false });
  try {
    return Object.freeze({
      recovery: decodeDealCreationRecovery(serialized),
      restored: true,
    });
  } catch (cause) {
    return Object.freeze({
      restored: true,
      error: cause instanceof Error ? cause.message : "Stored Deal Room creation recovery is invalid",
    });
  }
}

const erc20Abi = [
  {
    type: "function",
    name: "approve",
    stateMutability: "nonpayable",
    inputs: [{ name: "spender", type: "address" }, { name: "amount", type: "uint256" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "decimals",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
  },
  {
    type: "function",
    name: "symbol",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "string" }],
  },
] as const;

const DEMO_ADDRESS = "0x1111111111111111111111111111111111111111" as Address;
const DEMO_BUYER = "0x2222222222222222222222222222222222222222" as Address;
const ZERO_HASH = `0x${"0".repeat(64)}` as Hex;
const MODELED_EVALUATOR_POLICIES: readonly DiligenceEvaluatorPolicyDescriptor[] = DILIGENCE_RECIPES.map(
  (recipe, index) => ({
    recipe,
    policy_commitment: `0x${String(index + 1).padStart(64, "0")}` as Hex,
    display_schema: `modeled.${recipe}`,
    max_artifact_bytes: 1_048_576,
    policy_document_sha256: `sha256:${String(index + 1).padStart(64, "0")}`,
  }),
);
const evaluatorOptions = (): readonly DiligenceEvaluatorPolicyDescriptor[] =>
  deployment.evaluatorPolicyReleaseConfigured
    ? deployment.evaluatorPolicies
    : MODELED_EVALUATOR_POLICIES;

function evaluatorDescriptor(commitment: Hex): DiligenceEvaluatorPolicyDescriptor | undefined {
  return evaluatorOptions().find((descriptor) =>
    descriptor.policy_commitment.toLowerCase() === commitment.toLowerCase());
}
const DEMO_DEALS: ChainDeal[] = [
  {
    id: 14n,
    seller: DEMO_ADDRESS,
    buyer: zeroAddress,
    reservePrice: parseEther("0.018"),
    budgetCap: 0n,
    expiry: BigInt(Math.floor(Date.now() / 1000) + 6 * 86400),
    state: "Created",
    artifactHash: "0xeac5c25f464df027e7a351c2e393f55a32b15ab43b737653c1d0d21604918304",
    teeIdentity: DEMO_ADDRESS,
    scoreBand: "Negligible",
    computeCost: 0n,
    fee: 0n,
    resultHash: ZERO_HASH,
    resultComposeHash: ZERO_HASH,
    paymentToken: zeroAddress,
    evaluatorPolicyCommitment: ZERO_HASH,
    attestationEvidenceHash: ZERO_HASH,
    resultAuthorizationExpiry: 0n,
    attestationAuthorizationExpiry: 0n,
  },
  {
    id: 13n,
    seller: DEMO_ADDRESS,
    buyer: DEMO_BUYER,
    reservePrice: parseEther("0.012"),
    budgetCap: parseEther("0.03"),
    expiry: BigInt(Math.floor(Date.now() / 1000) + 2 * 86400),
    state: "Evaluated",
    artifactHash: "0x5df9d59b4abc2060ea2be241e69827f304f9e3f4caf52dcb50680eb500ccab22",
    teeIdentity: DEMO_ADDRESS,
    scoreBand: "High",
    computeCost: parseEther("0.0012"),
    fee: parseEther("0.000012"),
    resultHash: "0xadae63a83c8bb85e79ff3fbcb5961f360a7d5b0ba698b94a823881eb12e47fe0",
    resultComposeHash: "0xb41cd2b58e4360ee840f72d83a458e34ea6b2963159d379bb8dcccd26be9da5a",
    paymentToken: zeroAddress,
    evaluatorPolicyCommitment: MODELED_EVALUATOR_POLICIES[1].policy_commitment,
    attestationEvidenceHash: `0x${"a7".repeat(32)}`,
    resultAuthorizationExpiry: BigInt(Math.floor(Date.now() / 1000) + 300),
    attestationAuthorizationExpiry: BigInt(Math.floor(Date.now() / 1000) + 300),
  },
];

const TERMINAL: DealState[] = ["Accepted", "Rejected", "Expired"];

/**
 * Project only evidence the public browser actually has. The worker's
 * queued/awaiting-policy/running states are intentionally not inferred from an
 * accepted ciphertext POST; today they remain private runtime state.
 */
export function projectDealLifecycle(input: {
  state: DealState;
  ingress: DealIngressLifecycle;
}): DealLifecycleProjection {
  const resolved = input.state === "Accepted" || input.state === "Rejected";
  const hasCommittedResult = input.state === "Evaluated" || resolved;
  const expired = input.state === "Expired";

  if (expired) {
    return Object.freeze({
      headline: "Expired on Base Sepolia",
      explanation: "The room reached its terminal expiry state. This browser does not infer that any queued or running evaluation completed before expiry.",
      steps: lifecycleSteps(
        { key: "ciphertext", label: "Ciphertext", detail: "Prior ingress is not reconstructed", tone: "unobserved" },
        { key: "queue", label: "Queued", detail: "Historical worker state not public", tone: "unobserved" },
        { key: "policy", label: "Awaiting policy", detail: "Historical worker state not public", tone: "unobserved" },
        { key: "evaluation", label: "Running", detail: "Never inferred from elapsed time", tone: "unobserved" },
        { key: "result", label: "Bounded result", detail: "No committed result observed", tone: "pending" },
        { key: "resolution", label: "Expired", detail: "Terminal chain state", tone: "expired" },
      ),
    });
  }

  if (hasCommittedResult) {
    return Object.freeze({
      headline: resolved ? `Result ${input.state.toLowerCase()} on Base Sepolia` : "Bounded result committed on Base Sepolia",
      explanation: "The contract result transition is public. Queue, policy, and running events are shown as transitively completed prerequisites, not as separately observed CVM telemetry.",
      steps: lifecycleSteps(
        { key: "ciphertext", label: "Ciphertext", detail: "Required before evaluation; not replayed here", tone: "complete" },
        { key: "queue", label: "Queued", detail: "Transitively complete · event not public", tone: "complete" },
        { key: "policy", label: "Awaiting policy", detail: "Gate cleared · receipt not exposed here", tone: "complete" },
        { key: "evaluation", label: "Running", detail: "Finished · exact runtime trace private", tone: "complete" },
        { key: "result", label: "Bounded result", detail: "Commitment observed on-chain", tone: "complete" },
        { key: "resolution", label: resolved ? input.state : "Buyer decision", detail: resolved ? "Terminal chain state" : "Accept or reject remains open", tone: resolved ? "complete" : "current" },
      ),
    });
  }

  if (input.state === "Created") {
    return Object.freeze({
      headline: "Waiting for a buyer-defined cap and evaluator recipe",
      explanation: "No ciphertext can enter before the room is funded and the immutable evaluator policy is selected.",
      steps: lifecycleSteps(
        { key: "ciphertext", label: "Ciphertext", detail: "Locked until funding", tone: "pending" },
        { key: "queue", label: "Queued", detail: "Not entered", tone: "pending" },
        { key: "policy", label: "Awaiting policy", detail: "Evaluator recipe not selected", tone: "pending" },
        { key: "evaluation", label: "Running", detail: "Not started", tone: "pending" },
        { key: "result", label: "Bounded result", detail: "Not available", tone: "pending" },
        { key: "resolution", label: "Expired / settled", detail: "Terminal state not reached", tone: "pending" },
      ),
    });
  }

  const ingress = input.ingress;
  const ciphertextStep: DealLifecycleStep = ingress.phase === "accepted"
    ? { key: "ciphertext", label: "Ciphertext", detail: "Delegate acknowledgement matched locally", tone: "complete" }
    : ingress.phase === "delivery_uncertain"
      ? { key: "ciphertext", label: "Ciphertext", detail: "Delivery uncertain · retry retained pair", tone: "failed" }
      : ingress.phase === "failed_preflight"
        ? { key: "ciphertext", label: "Ciphertext", detail: "Failed before a confirmed POST · correct and retry", tone: "failed" }
        : ingress.phase === "retrying"
          ? { key: "ciphertext", label: "Ciphertext", detail: "Retrying the exact retained pair", tone: "current" }
          : ingress.phase === "authorizing"
            ? { key: "ciphertext", label: "Ciphertext", detail: "Awaiting wallet authorization", tone: "current" }
            : ingress.phase === "encrypting"
              ? { key: "ciphertext", label: "Ciphertext", detail: "Verifying, sealing, and sending", tone: "current" }
              : { key: "ciphertext", label: "Ciphertext", detail: "Seller upload not observed in this tab", tone: "current" };
  const acknowledged = ingress.phase === "accepted";
  const uncertain = ingress.phase === "delivery_uncertain";

  return Object.freeze({
    headline: acknowledged
      ? "Ciphertext acknowledged · internal phase remains bounded"
      : uncertain
        ? "Delivery failed closed · exact-pair retry available"
        : "Funded room · waiting for a verifiable ciphertext handoff",
    explanation: acknowledged
      ? "The acknowledgement proves only this upload response. Queued, awaiting-policy, and running are private worker states; the browser waits for a bounded on-chain result instead of inventing progress."
      : uncertain
        ? "The POST boundary may have been crossed. The original file and recovery receipt stay locked in memory so Retry cannot silently send different bytes."
        : "Another session may already have uploaded the artifact. Until a bounded result reaches the contract, this browser labels worker progress unobserved.",
    steps: lifecycleSteps(
      ciphertextStep,
      { key: "queue", label: "Queued", detail: acknowledged ? "Eligible · queue record not public" : uncertain ? "Unknown after ambiguous delivery" : "Not observed", tone: "unobserved" },
      { key: "policy", label: "Awaiting policy", detail: "Private runtime state · not asserted", tone: "unobserved" },
      { key: "evaluation", label: "Running", detail: "Private runtime state · not asserted", tone: "unobserved" },
      { key: "result", label: "Bounded result", detail: "Waiting for chain commitment", tone: "pending" },
      { key: "resolution", label: "Expired / settled", detail: "Room remains funded", tone: "pending" },
    ),
  });
}

function assetSymbol(token: Address): string {
  if (isZeroAddress(token)) return "ETH";
  if (deployment.usdcAddress && token.toLowerCase() === deployment.usdcAddress.toLowerCase()) return "USDC";
  return "TOKEN";
}

function sameAddress(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function formatAsset(value: bigint, token: Address, digits = 4): string {
  if (isZeroAddress(token)) return formatEth(value, digits);
  if (deployment.usdcAddress && token.toLowerCase() === deployment.usdcAddress.toLowerCase()) {
    const numeric = Number(formatUnits(value, 6));
    return `${numeric.toLocaleString(undefined, { maximumFractionDigits: Math.max(digits, 2) })} USDC`;
  }
  return `${value.toString()} token units`;
}

function amountInput(value: bigint, token: Address): string {
  if (isZeroAddress(token)) return formatUnits(value, 18);
  if (deployment.usdcAddress && token.toLowerCase() === deployment.usdcAddress.toLowerCase()) return formatUnits(value, 6);
  return value.toString();
}

async function assertApprovedUsdc(token: Address): Promise<6> {
  if (!deployment.usdcAddress || token.toLowerCase() !== deployment.usdcAddress.toLowerCase()) {
    throw new Error("Payment token is outside this deployment's frontend allowlist");
  }
  if (token.toLowerCase() !== BASE_SEPOLIA_USDC_ADDRESS.toLowerCase()) {
    throw new Error("Payment token is not Circle's canonical Base Sepolia USDC contract");
  }
  const releaseToken = computeVaultDeployment.token;
  if (!releaseToken || releaseToken.address.toLowerCase() !== token.toLowerCase()) {
    throw new Error("Canonical Base Sepolia USDC is not bound to this release's token policy");
  }
  const blockNumber = await publicClient.getBlockNumber();
  const [bytecode, decimals, symbol] = await Promise.all([
    publicClient.getBytecode({ address: token, blockNumber }),
    publicClient.readContract({ address: token, abi: erc20Abi, functionName: "decimals", blockNumber }),
    publicClient.readContract({ address: token, abi: erc20Abi, functionName: "symbol", blockNumber }),
  ]);
  if (!bytecode || bytecode === "0x") throw new Error("Configured USDC address has no bytecode on Base Sepolia");
  if (keccak256(bytecode).toLowerCase() !== releaseToken.codeHash.toLowerCase()) {
    throw new Error("Canonical Base Sepolia USDC runtime bytecode does not match the release pin");
  }
  if (decimals !== 6 || symbol !== "USDC") throw new Error("Configured token does not match the required USDC metadata (symbol USDC, 6 decimals)");
  return 6;
}

function configuredComposeHash(): Hex | undefined {
  const raw = deployment.composeHash.toLowerCase().replace(/^0x/, "");
  return /^[0-9a-f]{64}$/.test(raw) ? (`0x${raw}` as Hex) : undefined;
}

function statusTone(state: DealState): string {
  if (state === "Accepted") return "success";
  if (state === "Rejected" || state === "Expired") return "danger";
  if (state === "Evaluated") return "violet";
  if (state === "Funded") return "gold";
  return "mint";
}

function relativeExpiry(expiry: bigint): string {
  const seconds = Number(expiry) - Math.floor(Date.now() / 1000);
  if (seconds <= 0) return "expired";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return days > 0 ? `${days}d ${hours}h left` : `${Math.max(hours, 1)}h left`;
}

function RoleChip(props: { deal: ChainDeal }) {
  const me = () => wallet.account()?.toLowerCase();
  const label = () => {
    if (me() === props.deal.seller.toLowerCase()) return "You are the seller";
    if (me() === props.deal.buyer.toLowerCase()) return "You are the buyer";
    return props.deal.state === "Created" ? "Open to fund" : "Public room";
  };
  return <span class="role-chip"><WalletCards size={12} /> {label()}</span>;
}

function DealActions(props: {
  deal: ChainDeal;
  chainBacked: boolean;
  writeReady: boolean;
  transact: (label: string, action: (authorize: AuthorizeWrite) => Promise<Hex>) => Promise<boolean>;
  operationLock: DealRoomOperationLock;
  operationBusy: () => boolean;
  mutationLocked: () => boolean;
  artifactRecovery: () => ArtifactUploadRecovery | undefined;
  retainArtifactRecovery: (recovery: ArtifactUploadRecovery) => void;
  clearArtifactRecovery: (dealId: string) => void;
  onIngressLifecycleChange: (state: DealIngressLifecycle) => void;
}) {
  const initialRecovery = props.artifactRecovery();
  const [amount, setAmount] = createSignal(
    props.deal.state === "Evaluated" ? amountInput(props.deal.reservePrice, props.deal.paymentToken) : "0.025",
  );
  const [selectedEvaluatorPolicy, setSelectedEvaluatorPolicy] = createSignal<Hex>(
    props.deal.evaluatorPolicyCommitment !== ZERO_HASH
      ? props.deal.evaluatorPolicyCommitment
      : evaluatorOptions()[0].policy_commitment,
  );
  const [uploadFile, setUploadFile] = createSignal<File | undefined>(initialRecovery?.file);
  const [uploadReceipt, setUploadReceipt] = createSignal<ArtifactRecoveryReceipt | undefined>(initialRecovery?.receipt);
  const [uploadReceiptName, setUploadReceiptName] = createSignal(initialRecovery?.receiptName ?? "");
  const [uploadState, setUploadState] = createSignal<"idle" | "authorizing" | "encrypting" | "success" | "error">(initialRecovery ? "error" : "idle");
  const [uploadMessage, setUploadMessage] = createSignal(initialRecovery?.message ?? "");
  let recoveryReceiptRead = 0;
  let uploadFileInput!: HTMLInputElement;
  let uploadReceiptInput!: HTMLInputElement;
  const me = () => wallet.account()?.toLowerCase();
  const isBuyer = () => me() === props.deal.buyer.toLowerCase();
  const isSeller = () => me() === props.deal.seller.toLowerCase();
  const trustedPaymentToken = () => isZeroAddress(props.deal.paymentToken)
    || Boolean(deployment.usdcAddress && props.deal.paymentToken.toLowerCase() === deployment.usdcAddress.toLowerCase());
  const uploadReceiptMatches = () => uploadReceipt()?.artifact_commitment === props.deal.artifactHash.toLowerCase();
  const canExpire = () => Number(props.deal.expiry) <= Math.floor(Date.now() / 1000) && !TERMINAL.includes(props.deal.state);
  const selectedEvaluator = () => evaluatorDescriptor(selectedEvaluatorPolicy());
  const uploadRecoveryPending = () => props.artifactRecovery() !== undefined;
  const draftMutationIsAllowed = (explicitRecoveryDiscard = false) => {
    if (explicitRecoveryDiscard && !uploadRecoveryPending()) return false;
    return dealRoomDraftMutationIsAllowed({
      operationInFlight: props.operationBusy(),
      uploadRecoveryPending: props.mutationLocked() && !props.operationBusy(),
      explicitRecoveryDiscard,
    });
  };
  const uploadDraftLocked = () => !draftMutationIsAllowed();

  const fund = async (authorize: AuthorizeWrite) => {
    const evaluatorPolicyCommitment = selectedEvaluatorPolicy();
    const requestedAmount = amount();
    if (
      !deployment.evaluatorPolicyReleaseConfigured
      || !deployment.evaluatorPolicies.some((descriptor) =>
        descriptor.policy_commitment.toLowerCase() === evaluatorPolicyCommitment.toLowerCase())
    ) {
      throw new Error("Choose one evaluator recipe from the exact frozen Diligence release set");
    }
    if (!isZeroAddress(props.deal.paymentToken)) {
      const token = props.deal.paymentToken;
      const decimals = await assertApprovedUsdc(token);
      const units = parseUnits(requestedAmount, decimals);
      if (units < props.deal.reservePrice) {
        throw new Error("Buyer budget cap must meet or exceed the seller reserve");
      }
      const approval = await authorize(({ client, account, contract }) => client.writeContract({
          account,
          chain: baseSepolia,
          address: token,
          abi: erc20Abi,
          functionName: "approve",
          args: [contract, units],
        }));
      const approvalReceipt = await publicClient.waitForTransactionReceipt({ hash: approval });
      if (approvalReceipt.status !== "success") throw new Error("USDC approval reverted on Base Sepolia");
      // Re-check after the separate approval transaction. This keeps a proxy
      // upgrade or network-state change from silently crossing the two-step
      // approve -> fund boundary.
      await assertApprovedUsdc(token);
      return authorize(({ client, account, contract }) => client.writeContract({
          account,
          chain: baseSepolia,
          address: contract,
          abi: diligenceRoomAbi,
          functionName: "fundDealERC20",
          args: [props.deal.id, units, evaluatorPolicyCommitment],
        }));
    }
    const value = parseEther(requestedAmount);
    if (value < props.deal.reservePrice) {
      throw new Error("Buyer budget cap must meet or exceed the seller reserve");
    }
    return authorize(({ client, account, contract }) => client.writeContract({
        account,
        chain: baseSepolia,
        address: contract,
        abi: diligenceRoomAbi,
        functionName: "fundDeal",
        args: [props.deal.id, evaluatorPolicyCommitment],
        value,
      }));
  };

  const accept = async (authorize: AuthorizeWrite) => {
    const requestedAmount = amount();
    let offer = parseEther(requestedAmount);
    if (!isZeroAddress(props.deal.paymentToken)) {
      const decimals = await assertApprovedUsdc(props.deal.paymentToken);
      offer = parseUnits(requestedAmount, decimals);
    }
    if (offer < props.deal.reservePrice) {
      throw new Error("Accepted seller payment must meet the room reserve");
    }
    if (offer + props.deal.computeCost + props.deal.fee > props.deal.budgetCap) {
      throw new Error("Seller payment plus the fixed compute tariff exceeds the buyer budget cap");
    }
    return authorize(({ client, account, contract }) => client.writeContract({
        account,
        chain: baseSepolia,
        address: contract,
        abi: diligenceRoomAbi,
        functionName: "acceptDeal",
        args: [props.deal.id, offer],
      }));
  };

  const simpleWrite = async (fn: "rejectDeal" | "expireDeal", authorize: AuthorizeWrite) => {
    return authorize(({ client, account, contract }) => client.writeContract({ account, chain: baseSepolia, address: contract, abi: diligenceRoomAbi, functionName: fn, args: [props.deal.id] }));
  };

  const upload = async (retry = false) => {
    if (!props.writeReady || !deployment.artifactUploadEnabled || retry !== uploadRecoveryPending()) return;
    if ((!retry && props.mutationLocked()) || (retry && props.operationBusy())) return;
    const file = uploadFile();
    const receipt = uploadReceipt();
    if (!file || !receipt || !uploadReceiptMatches()) return;
    await runDealRoomOperation(
      props.operationLock,
      "artifact_upload",
      `Authorize encrypted ingress for room ${props.deal.id.toString()}`,
      async (lease) => {
        let uploadBoundaryEntered = false;
        setUploadMessage("");
        try {
          setUploadState("authorizing");
          props.onIngressLifecycleChange({ phase: retry ? "retrying" : "authorizing" });
          const authorization = await wallet.authorizeDealUpload(props.deal.id);
          const walletVersion = wallet.authorizationVersion();
          if (
            !props.operationLock.isCurrent(lease)
            || !wallet.isCorrectChain()
            || wallet.account()?.toLowerCase() !== authorization.address.toLowerCase()
          ) {
            throw new Error("Wallet session changed before encrypted upload; authorize it again");
          }
          setUploadState("encrypting");
          props.onIngressLifecycleChange({ phase: "encrypting" });
          const result = await uploadEncryptedArtifact(
            file,
            receipt,
            props.deal.id,
            authorization.access_token,
            props.deal.artifactHash as Hex,
            props.deal.evaluatorPolicyCommitment,
            { onPostStarted: () => { uploadBoundaryEntered = true; } },
          );
          if (
            !props.operationLock.isCurrent(lease)
            || wallet.authorizationVersion() !== walletVersion
            || !wallet.isCorrectChain()
            || wallet.account()?.toLowerCase() !== authorization.address.toLowerCase()
          ) throw new Error("Wallet session changed while the upload was in flight. The delegate may have received it; retry the retained artifact pair.");
          if (!result.received) throw new Error("Delegate did not acknowledge the encrypted artifact");
          props.clearArtifactRecovery(props.deal.id.toString());
          setUploadState("success");
          setUploadMessage(`Encrypted artifact accepted · ciphertext receipt ${result.ciphertextSha256.slice(0, 18)}…`);
          props.onIngressLifecycleChange({
            phase: "accepted",
            ciphertextReceipt: result.ciphertextSha256,
          });
          setUploadFile(undefined);
          setUploadReceipt(undefined);
          setUploadReceiptName("");
          uploadFileInput.value = "";
          uploadReceiptInput.value = "";
          return true;
        } catch (cause) {
          const message = cause instanceof Error ? cause.message : "Encrypted upload failed";
          const recoveryMessage = uploadBoundaryEntered || uploadRecoveryPending()
            ? `${message} Delivery may be uncertain. The original file and recovery receipt remain locked for exact-artifact retry or explicit discard.`
            : message;
          if (uploadBoundaryEntered || uploadRecoveryPending()) {
            props.retainArtifactRecovery(Object.freeze({
              dealId: props.deal.id.toString(),
              file,
              receipt,
              receiptName: uploadReceiptName(),
              message: recoveryMessage,
            }));
          }
          setUploadState("error");
          setUploadMessage(recoveryMessage);
          props.onIngressLifecycleChange({
            phase: uploadBoundaryEntered || uploadRecoveryPending()
              ? "delivery_uncertain"
              : "failed_preflight",
          });
          return false;
        }
      },
    );
  };

  const readRecoveryReceipt = async (file: File | undefined) => {
    if (!draftMutationIsAllowed()) return;
    const request = ++recoveryReceiptRead;
    setUploadReceipt(undefined);
    setUploadReceiptName("");
    setUploadMessage("");
    setUploadState("idle");
    if (!file) return;
    if (file.size <= 0 || file.size > 4096) {
      setUploadState("error");
      setUploadMessage("Recovery receipt must be a JSON file no larger than 4 KB");
      return;
    }
    let bytes: Uint8Array | undefined;
    try {
      bytes = new Uint8Array(await file.arrayBuffer());
      if (request !== recoveryReceiptRead || !draftMutationIsAllowed()) return;
      const receipt = parseArtifactRecoveryReceipt(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
      if (receipt.artifact_commitment !== props.deal.artifactHash.toLowerCase()) {
        throw new Error("Recovery receipt does not match this room's on-chain artifact commitment");
      }
      if (request !== recoveryReceiptRead || !draftMutationIsAllowed()) return;
      setUploadReceipt(receipt);
      setUploadReceiptName(file.name);
      setUploadMessage("Private recovery receipt matches the on-chain v2 commitment");
    } catch (cause) {
      if (request === recoveryReceiptRead && draftMutationIsAllowed()) {
        setUploadState("error");
        setUploadMessage(cause instanceof Error ? cause.message : "Recovery receipt is invalid");
      }
    } finally {
      bytes?.fill(0);
    }
  };

  const selectUploadFile = (file: File | undefined) => {
    if (!draftMutationIsAllowed()) return;
    ++recoveryReceiptRead;
    setUploadFile(file);
    setUploadState("idle");
    setUploadMessage("");
  };

  const discardUploadRecovery = () => {
    if (!draftMutationIsAllowed(true)) return;
    ++recoveryReceiptRead;
    props.clearArtifactRecovery(props.deal.id.toString());
    setUploadFile(undefined);
    setUploadReceipt(undefined);
    setUploadReceiptName("");
    setUploadState("idle");
    setUploadMessage("");
    props.onIngressLifecycleChange({ phase: "idle" });
    uploadFileInput.value = "";
    uploadReceiptInput.value = "";
  };

  return (
    <div class="deal-actions" aria-busy={props.mutationLocked()}>
      <Show when={props.deal.state === "Created"}>
        <fieldset class="evaluator-picker" disabled={props.mutationLocked()}>
          <legend>Buyer-selected evaluator recipe</legend>
          <p>Funding atomically locks one reviewed, deterministic recipe for this room. It cannot execute arbitrary code, use the network, or be changed later.</p>
          <div class="evaluator-options">
            <For each={evaluatorOptions()}>{(descriptor) => {
              const copy = DILIGENCE_RECIPE_COPY[descriptor.recipe];
              return (
                <label class={selectedEvaluatorPolicy() === descriptor.policy_commitment ? "selected" : ""}>
                  <input
                    type="radio"
                    name={`deal-${props.deal.id.toString()}-evaluator`}
                    value={descriptor.policy_commitment}
                    checked={selectedEvaluatorPolicy() === descriptor.policy_commitment}
                    disabled={props.mutationLocked()}
                    onChange={() => {
                      if (draftMutationIsAllowed()) setSelectedEvaluatorPolicy(descriptor.policy_commitment);
                    }}
                  />
                  <span><strong>{copy.label}</strong><small>{copy.summary}</small><code>{shortAddress(descriptor.policy_commitment, 7)}</code></span>
                </label>
              );
            }}</For>
          </div>
          <Show when={selectedEvaluator()}>{(descriptor) => <p class="evaluator-selection"><ShieldCheck size={13} /> Accepts {DILIGENCE_RECIPE_COPY[descriptor().recipe].accepts} · maximum plaintext 1 MiB</p>}</Show>
        </fieldset>
        <label>
          <span>Buyer budget cap ({assetSymbol(props.deal.paymentToken)})</span>
          <div class="inline-input"><input value={amount()} inputmode="decimal" disabled={props.mutationLocked()} onInput={(event) => {
            if (draftMutationIsAllowed()) setAmount(event.currentTarget.value);
          }} /><span>CAP</span></div>
        </label>
          <button class="primary-button" type="button" disabled={!props.writeReady || !trustedPaymentToken() || props.mutationLocked()} onClick={() => void props.transact("Fund room", fund)}>
          <HandCoins size={16} /> Fund room
        </button>
        <Show when={!trustedPaymentToken()}><p class="modeled-note"><TriangleAlert size={13} /> This room names a token outside this deployment's frontend allowlist. Inspect it on-chain; this UI will not approve or fund it.</p></Show>
      </Show>
      <Show when={props.deal.state === "Funded" && isSeller()}>
        <div class="artifact-ingress">
          <label class="file-drop compact-drop">
            <input ref={uploadFileInput} type="file" disabled={uploadDraftLocked()} onChange={(event) => selectUploadFile(event.currentTarget.files?.[0])} />
            <FileUp size={20} />
            <span><strong>{uploadFile()?.name ?? "1. Select the original artifact"}</strong><small>1 byte–1 MiB · fixed-size encrypted transport</small></span>
          </label>
          <label class="file-drop compact-drop">
            <input ref={uploadReceiptInput} type="file" accept="application/json,.json" disabled={uploadDraftLocked()} onChange={(event) => void readRecoveryReceipt(event.currentTarget.files?.[0])} />
            <FileKey size={20} />
            <span><strong>{uploadReceiptName() || "2. Select its private recovery receipt"}</strong><small>The secret is verified locally, then sealed inside the TEE ciphertext</small></span>
          </label>
          <Show when={!uploadRecoveryPending()}>
            <button class="primary-button full" type="button" disabled={!props.writeReady || !deployment.artifactUploadEnabled || !uploadFile() || !uploadReceiptMatches() || props.mutationLocked()} onClick={() => void upload()}>
            {uploadState() === "authorizing" || uploadState() === "encrypting" ? <LoaderCircle class="spin" size={16} /> : <LockKeyhole size={16} />}
            {uploadState() === "authorizing" ? "Authorize in wallet…" : uploadState() === "encrypting" ? "Verify, encrypt, and upload…" : "Authorize encrypted ingress"}
            </button>
          </Show>
          <Show when={uploadRecoveryPending()}>
            <div class="artifact-recovery-card">
              <RefreshCw size={16} />
              <div><strong>Unresolved artifact delivery retained</strong><span>The exact original file and private recovery receipt are locked in memory. Stay on this page; retry that pair, or discard it before selecting anything else.</span></div>
              <div class="artifact-recovery-actions">
                <button class="secondary-button" type="button" disabled={!props.writeReady || !deployment.artifactUploadEnabled || props.operationBusy()} onClick={() => void upload(true)}>Retry retained pair</button>
                <button class="ghost-button" type="button" disabled={props.operationBusy()} onClick={discardUploadRecovery}>Discard retained pair</button>
              </div>
            </div>
          </Show>
          <Show when={uploadMessage()}><p class={`ingress-result ${uploadState()}`} role={uploadState() === "error" ? "alert" : "status"}>{uploadState() === "success" || (uploadState() === "idle" && uploadReceiptMatches()) ? <CheckCircle2 size={13} /> : <TriangleAlert size={13} />}{uploadMessage()}</p></Show>
          <Show when={!deployment.artifactUploadEnabled}><p class="modeled-note"><Sparkles size={13} /> Browser ingress remains locked until the fresh CVM, compose policy, and independent quote-verification path are configured.</p></Show>
        </div>
      </Show>
      <Show when={props.deal.state === "Evaluated" && isBuyer()}>
        <label>
          <span>Seller payment ({assetSymbol(props.deal.paymentToken)})</span>
          <div class="inline-input"><input value={amount()} inputmode="decimal" disabled={props.mutationLocked()} onInput={(event) => {
            if (draftMutationIsAllowed()) setAmount(event.currentTarget.value);
          }} /><span>OFFER</span></div>
        </label>
        <div class="action-pair">
          <button class="primary-button" type="button" disabled={!props.writeReady || props.mutationLocked()} onClick={() => void props.transact("Accept result", accept)}><CheckCircle2 size={16} /> Accept</button>
          <button class="danger-button" type="button" disabled={!props.writeReady || props.mutationLocked()} onClick={() => void props.transact("Reject result", (authorize) => simpleWrite("rejectDeal", authorize))}><XCircle size={16} /> Reject</button>
        </div>
      </Show>
      <Show when={canExpire()}>
        <button class="secondary-button" type="button" disabled={!props.writeReady || props.mutationLocked()} onClick={() => void props.transact("Expire room", (authorize) => simpleWrite("expireDeal", authorize))}><Clock3 size={16} /> Expire and settle refund</button>
      </Show>
      <Show when={!props.writeReady && !TERMINAL.includes(props.deal.state)}>
        <p class="modeled-note"><Sparkles size={13} /> {props.chainBacked
          ? "Live chain read · writes locked"
          : "Modeled preview—writes unlock after the fresh deployment is verified."}</p>
      </Show>
    </div>
  );
}

function DealCard(props: {
  deal: ChainDeal;
  chainBacked: boolean;
  writeReady: boolean;
  modeled: boolean;
  inspectEvidence: (context: VerificationContext) => void;
  transact: (label: string, action: (authorize: AuthorizeWrite) => Promise<Hex>) => Promise<boolean>;
  operationLock: DealRoomOperationLock;
  operationBusy: () => boolean;
  mutationLocked: () => boolean;
  artifactRecovery: () => ArtifactUploadRecovery | undefined;
  retainArtifactRecovery: (recovery: ArtifactUploadRecovery) => void;
  clearArtifactRecovery: (dealId: string) => void;
}) {
  const [ingressLifecycle, setIngressLifecycle] = createSignal<DealIngressLifecycle>(
    props.artifactRecovery()
      ? { phase: "delivery_uncertain" }
      : { phase: "idle" },
  );
  const lifecycle = createMemo(() => projectDealLifecycle({
    state: props.deal.state,
    ingress: ingressLifecycle(),
  }));

  return (
    <article class="deal-card">
      <div class="deal-card-head">
        <div>
          <span class="mono room-id">ROOM / {props.deal.id.toString().padStart(4, "0")}</span>
          <h3>{props.deal.scoreBand !== "Negligible" && props.deal.state !== "Created" ? `${props.deal.scoreBand} bounded signal` : "Private artifact diligence"}</h3>
        </div>
        <div class="deal-card-states"><span class={`status-badge ${statusTone(props.deal.state)}`}><span class="status-dot" />{props.deal.state}</span><Show when={props.modeled}><span class="status-badge modeled"><span class="status-dot" />MODELED DATA</span></Show></div>
      </div>
      <div class="deal-proof-strip">
        <div><FileKey size={14} /><span>Artifact</span><code>{shortAddress(props.deal.artifactHash, 7)}</code></div>
        <div><LockKeyhole size={14} /><span>TEE identity</span><code>{shortAddress(props.deal.teeIdentity, 5)}</code></div>
        <div><Clock3 size={14} /><span>Window</span><strong>{relativeExpiry(props.deal.expiry)}</strong></div>
      </div>
      <div class="deal-policy-strip">
        <ShieldCheck size={15} />
        <div>
          <small>IMMUTABLE EVALUATOR RECIPE</small>
          <strong>{props.deal.evaluatorPolicyCommitment === ZERO_HASH
            ? "Buyer selects on funding"
            : evaluatorDescriptor(props.deal.evaluatorPolicyCommitment)
              ? DILIGENCE_RECIPE_COPY[evaluatorDescriptor(props.deal.evaluatorPolicyCommitment)!.recipe].label
              : "Unrecognized policy commitment"}</strong>
        </div>
        <code>{props.deal.evaluatorPolicyCommitment === ZERO_HASH ? "not selected" : shortAddress(props.deal.evaluatorPolicyCommitment, 8)}</code>
      </div>
      <div class="deal-economics">
        <div><small>Seller reserve</small><strong>{formatAsset(props.deal.reservePrice, props.deal.paymentToken)}</strong></div>
        <div><small>Buyer cap</small><strong>{props.deal.budgetCap > 0n ? formatAsset(props.deal.budgetCap, props.deal.paymentToken) : "Not funded"}</strong></div>
        <div><small>Compute + fee</small><strong>{props.deal.computeCost > 0n ? formatAsset(props.deal.computeCost + props.deal.fee, props.deal.paymentToken) : "Pending"}</strong></div>
      </div>
      <section class="deal-lifecycle" aria-label={`Bounded lifecycle for Deal Room ${props.deal.id.toString()}`}>
        <div class="deal-lifecycle-head">
          <div><small>BOUNDED ROOM LIFECYCLE</small><strong>{lifecycle().headline}</strong></div>
          <span class={props.modeled ? "modeled" : "live"}>{props.modeled ? "MODELED PROJECTION" : "PUBLIC + LOCAL EVIDENCE"}</span>
        </div>
        <ol>
          <For each={lifecycle().steps}>{(step, index) => (
            <li class={step.tone} aria-current={step.tone === "current" ? "step" : undefined}>
              <span>{String(index() + 1).padStart(2, "0")}</span>
              <div><strong>{step.label}</strong><small>{step.detail}</small></div>
            </li>
          )}</For>
        </ol>
        <p>{lifecycle().explanation}</p>
        <Show when={ingressLifecycle().ciphertextReceipt} keyed>
          {(receipt) => <div class="deal-lifecycle-receipt"><ShieldCheck size={13} /><span>LOCAL ACKNOWLEDGEMENT</span><code>{shortAddress(receipt, 10)}</code></div>}
        </Show>
      </section>
      <Show when={props.deal.state === "Evaluated" || props.deal.state === "Accepted" || props.deal.state === "Rejected"}>
        <div class="bounded-result">
          <div class="result-orb"><ShieldCheck size={19} /></div>
          <div><small>BOUNDED EVALUATION</small><strong>{props.deal.scoreBand}</strong></div>
          <div><small>RESULT COMMITMENT</small><code>{shortAddress(props.deal.resultHash, 8)}</code></div>
          <div><small>COMPOSE BINDING</small><code>{shortAddress(props.deal.resultComposeHash, 8)}</code></div>
          <div><small>ATTESTATION COMMITMENT</small><code>{shortAddress(props.deal.attestationEvidenceHash, 8)}</code></div>
        </div>
        <div class="deal-card-foot">
          <span>{props.modeled
            ? "Illustrative commitment · no execution, QVL, raw quote, or Intel evidence"
            : "Contract/worker-reported binding · not independently verified by this browser; no raw quote or Intel collateral checked"}</span>
          <button
            class="proof-button"
            type="button"
            aria-label={`Inspect evidence for Deal Room ${props.deal.id.toString()} in Trust Center`}
            onClick={() => props.inspectEvidence(createDealResultVerificationContext(props.deal, {
              modeled: props.modeled,
              contractAddress: deployment.contractAddress,
            }))}
          >
            Inspect in Trust Center <ArrowRight size={13} />
          </button>
        </div>
      </Show>
      <div class="deal-card-foot">
        <RoleChip deal={props.deal} />
        <span>Seller {shortAddress(props.deal.seller)}</span>
      </div>
      <DealActions
        deal={props.deal}
        chainBacked={props.chainBacked}
        writeReady={props.writeReady}
        transact={props.transact}
        operationLock={props.operationLock}
        operationBusy={props.operationBusy}
        mutationLocked={props.mutationLocked}
        artifactRecovery={props.artifactRecovery}
        retainArtifactRecovery={props.retainArtifactRecovery}
        clearArtifactRecovery={props.clearArtifactRecovery}
        onIngressLifecycleChange={setIngressLifecycle}
      />
    </article>
  );
}

export function DealRoom(props: { inspectEvidence: (context: VerificationContext) => void }) {
  const restoredCreation = readStoredDealCreationRecovery();
  const [deals, setDeals] = createSignal<ChainDeal[]>(deployment.contractAddress ? [] : DEMO_DEALS);
  const [chainBacked, setChainBacked] = createSignal(false);
  const [loading, setLoading] = createSignal(Boolean(deployment.contractAddress));
  const [loadError, setLoadError] = createSignal("");
  const [loadFailure, setLoadFailure] = createSignal<DealListFailure>();
  const [dealSnapshot, setDealSnapshot] = createSignal<DealSnapshot>();
  const [dealContinuation, setDealContinuation] = createSignal<DealPageCursor>();
  const [exactDealId, setExactDealId] = createSignal("");
  const [exactLookup, setExactLookup] = createSignal<ExactDealLookup>();
  const [exactLookupError, setExactLookupError] = createSignal("");
  const [exactLookupLoading, setExactLookupLoading] = createSignal(false);
  const [filter, setFilter] = createSignal<DealFilter>("all");
  const [showCreate, setShowCreate] = createSignal(false);
  const [reserve, setReserve] = createSignal("0.015");
  const [expiryDays, setExpiryDays] = createSignal("7");
  const [settlement, setSettlement] = createSignal<"eth" | "erc20">("eth");
  const [paymentToken] = createSignal(deployment.usdcAddress ?? "");
  const [artifactName, setArtifactName] = createSignal("");
  const [artifactHash, setArtifactHash] = createSignal<Hex>();
  const [artifactReceipt, setArtifactReceipt] = createSignal<ArtifactRecoveryReceipt>();
  const [receiptDownloaded, setReceiptDownloaded] = createSignal(false);
  const [artifactError, setArtifactError] = createSignal("");
  const [hashing, setHashing] = createSignal(false);
  const [tx, setTx] = createSignal<TxState>({ kind: "idle", label: "" });
  const [activeOperation, setActiveOperation] = createSignal<DealRoomOperationLease>();
  const [artifactUploadRecovery, setArtifactUploadRecovery] = createSignal<ArtifactUploadRecovery>();
  const [dealCreationRecovery, setDealCreationRecovery] = createSignal<DealCreationRecovery | undefined>(restoredCreation.recovery);
  const [dealCreationResolution, setDealCreationResolution] = createSignal<DealCreationResolution>();
  const [dealCreationStorageError, setDealCreationStorageError] = createSignal(restoredCreation.error ?? "");
  const [creationRecoveryRestored] = createSignal(restoredCreation.restored);
  const [pendingNative, setPendingNative] = createSignal(0n);
  const [pendingUsdc, setPendingUsdc] = createSignal(0n);
  const [writePolicy, setWritePolicy] = createSignal<ContractWritePolicy>();
  const [policyMessage, setPolicyMessage] = createSignal("");
  const operationLock = new DealRoomOperationLock((active) => setActiveOperation(active));
  let artifactPreparation = 0;
  let dealLoadGeneration = 0;
  let exactLookupGeneration = 0;

  const contractConfigured = () => Boolean(deployment.contractAddress);
  const writesReady = () => chainBacked() && deployment.contractWritesEnabled && Boolean(writePolicy());
  const operationBusy = () => activeOperation() !== undefined;
  const mutationLocked = () => operationBusy() || artifactUploadRecovery() !== undefined || loading();
  const draftMutationIsAllowed = () => dealRoomDraftMutationIsAllowed({
    operationInFlight: operationBusy() || loading(),
    uploadRecoveryPending: artifactUploadRecovery() !== undefined,
  });
  const creationDraftIsAllowed = () =>
    writesReady()
    && draftMutationIsAllowed()
    && dealCreationRecovery() === undefined
    && dealCreationStorageError() === "";
  const creationLocked = () =>
    !writesReady()
    || mutationLocked()
    || dealCreationRecovery() !== undefined
    || dealCreationStorageError() !== "";
  const creationRetryAllowed = () => {
    const status = dealCreationResolution()?.status;
    return status === "reverted" || status === "not_broadcast";
  };
  const retainArtifactRecovery = (recovery: ArtifactUploadRecovery) => {
    setArtifactUploadRecovery((current) => {
      if (current && current.dealId !== recovery.dealId) return current;
      return Object.freeze(recovery);
    });
  };
  const clearArtifactRecovery = (dealId: string) => {
    setArtifactUploadRecovery((current) => current?.dealId === dealId ? undefined : current);
  };
  const persistDealCreationRecovery = (
    recovery: DealCreationRecovery,
    mustPersistBeforePrompt: boolean,
  ): void => {
    const normalized = createDealCreationRecovery(recovery.intent, recovery.transactionHash);
    try {
      window.localStorage.setItem(
        DEAL_CREATION_RECOVERY_STORAGE_KEY,
        encodeDealCreationRecovery(normalized),
      );
      setDealCreationStorageError("");
      setDealCreationRecovery(normalized);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Browser recovery storage is unavailable";
      setDealCreationStorageError(message);
      if (mustPersistBeforePrompt) throw new Error(`Creation was not broadcast because recovery metadata could not be persisted: ${message}`);
      // A hash may already exist. Retain it in memory even when durable storage
      // refused the immediate hash update; the previously persisted hashless
      // intent still fails closed after a reload.
      setDealCreationRecovery(normalized);
    }
  };
  const clearDealCreationRecovery = (): boolean => {
    try {
      window.localStorage.removeItem(DEAL_CREATION_RECOVERY_STORAGE_KEY);
    } catch (cause) {
      setDealCreationStorageError(cause instanceof Error ? cause.message : "Could not clear browser recovery storage");
      return false;
    }
    setDealCreationRecovery(undefined);
    setDealCreationResolution(undefined);
    setDealCreationStorageError("");
    return true;
  };
  const creationRuntimeContext = () => ({
    account: wallet.account(),
    chainId: wallet.chainId(),
    releaseSha: deployment.releaseSha,
    contract: deployment.contractAddress,
  });

  const inspectContractWritePolicy = async (expectedAccount?: Address): Promise<ContractWritePolicy | undefined> => {
    const contract = deployment.contractAddress;
    setWritePolicy(undefined);
    if (!contract) {
      setPolicyMessage("No fresh DiligenceRoom address is configured.");
      if (expectedAccount) throw new Error("No fresh DiligenceRoom address is configured");
      return undefined;
    }
    if (!deployment.contractWritesEnabled) {
      setPolicyMessage("Contract reads may be available; release-authorized writes are disabled in this build.");
      if (expectedAccount) throw new Error("Release-authorized DiligenceRoom writes are disabled in this build");
      return undefined;
    }
    const composeHash = configuredComposeHash();
    if (
      !deployment.contractCodeHash
      || !deployment.contractDeveloper
      || !deployment.contractInitialDeveloper
      || !deployment.contractReleaseGovernanceController
      || !deployment.resultVerifierAddress
      || !deployment.attestationVerifierAddress
      || !deployment.attestationReleasePolicyHash
      || !deployment.evaluatorPolicyReleaseConfigured
      || !deployment.evaluatorPolicySetRoot
      || !deployment.teeIdentity
      || !composeHash
    ) {
      setPolicyMessage("Writes are locked because the bytecode, trust root, policy, compose, or TEE identity release pins are incomplete.");
      if (expectedAccount) throw new Error("DiligenceRoom release pins are incomplete");
      return undefined;
    }
    try {
      const accountBefore = wallet.account();
      const chainBefore = wallet.chainId();
      if (expectedAccount && accountBefore?.toLowerCase() !== expectedAccount.toLowerCase()) {
        throw new Error("Wallet account changed before the contract policy inspection");
      }
      if (expectedAccount && chainBefore !== baseSepolia.id) {
        throw new Error("Wallet chain changed before the contract policy inspection");
      }
      const {
        blockNumber,
        bytecode,
        productionRelease,
        developer,
        initialDeveloper,
        releaseGovernanceController,
        pendingDeveloper,
        pendingDeveloperActivatesAt,
        resultVerifier,
        resultVerifierFrozen,
        attestationVerifier,
        attestationReleasePolicyHash,
        attestationBindingFrozen,
        composeApprovalRequired: composeRequired,
        teeIdentityApprovalRequired: teeRequired,
        approvalRequirementsFrozen: requirementsFrozen,
        composeAdditionsFrozen,
        teeIdentityAdditionsFrozen: teeAdditionsFrozen,
        feeBpsFrozen,
        computeSettlementPolicyEnabled: computePolicyEnabled,
        approvedComposeCount,
        approvedTeeIdentityCount: approvedTeeCount,
        pendingComposeCount,
        pendingTeeIdentityCount: pendingTeeCount,
        approvedEvaluatorPolicyCount,
        pendingEvaluatorPolicyCount,
        evaluatorPolicySetFrozen,
        evaluatorPolicySetRoot,
        evaluatorPolicies,
        evaluatorPoliciesApproved,
        teeComposeHash,
        composeApproved,
      } = await loadDiligenceWritePolicySnapshot(contract, deployment.teeIdentity, composeHash);
      if (
        expectedAccount
        && (
          wallet.account()?.toLowerCase() !== expectedAccount.toLowerCase()
          || wallet.chainId() !== baseSepolia.id
        )
      ) throw new Error("Wallet account or chain changed during the one-block contract policy inspection");
      if (!bytecode || bytecode === "0x") throw new Error("Configured DiligenceRoom has no bytecode on Base Sepolia");
      if (keccak256(bytecode) !== deployment.contractCodeHash) throw new Error("DiligenceRoom runtime bytecode does not match the release pin");
      if (!productionRelease) throw new Error("DiligenceRoom was not constructor-bound as a production release");
      if (initialDeveloper.toLowerCase() !== deployment.contractInitialDeveloper.toLowerCase()) throw new Error("DiligenceRoom initial developer does not match the release pin");
      if (releaseGovernanceController.toLowerCase() !== deployment.contractReleaseGovernanceController.toLowerCase()) throw new Error("DiligenceRoom immutable governance controller does not match the release pin");
      if (developer.toLowerCase() !== deployment.contractDeveloper.toLowerCase()) throw new Error("DiligenceRoom developer role does not match the release pin");
      if (developer.toLowerCase() !== releaseGovernanceController.toLowerCase()) throw new Error("DiligenceRoom governance controller has not accepted the delayed developer handoff");
      if (
        pendingDeveloper.toLowerCase() !== zeroAddress
        || pendingDeveloperActivatesAt !== 0n
      ) throw new Error("DiligenceRoom has an unexpected pending developer handoff");
      if (resultVerifier.toLowerCase() !== deployment.resultVerifierAddress.toLowerCase()) throw new Error("DiligenceRoom result verifier does not match the release pin");
      if (!resultVerifierFrozen) throw new Error("DiligenceRoom result verifier is not permanently frozen");
      if (attestationVerifier.toLowerCase() !== deployment.attestationVerifierAddress.toLowerCase()) throw new Error("DiligenceRoom independent QVL verifier does not match the release pin");
      if (attestationReleasePolicyHash.toLowerCase() !== deployment.attestationReleasePolicyHash.toLowerCase()) throw new Error("DiligenceRoom independent QVL policy hash does not match the release pin");
      if (!attestationBindingFrozen) throw new Error("DiligenceRoom independent QVL binding is not permanently frozen");
      if (!composeRequired || !teeRequired) throw new Error("DiligenceRoom mandatory compose and TEE identity approval gates are not both enabled");
      if (!requirementsFrozen) throw new Error("DiligenceRoom approval requirements are not permanently frozen on-chain");
      if (!composeAdditionsFrozen || !teeAdditionsFrozen) throw new Error("DiligenceRoom compose and TEE admission additions are not permanently closed");
      if (!feeBpsFrozen || !computePolicyEnabled) throw new Error("DiligenceRoom settlement policy is not permanently release-bound");
      if (approvedComposeCount !== 1n || approvedTeeCount !== 1n) throw new Error("DiligenceRoom active admission set is not exactly one compose and one TEE identity");
      if (pendingComposeCount !== 0n || pendingTeeCount !== 0n) throw new Error("DiligenceRoom has an unexpected pending admission proposal");
      if (!evaluatorPolicySetFrozen) throw new Error("DiligenceRoom evaluator policy set is not permanently frozen");
      if (approvedEvaluatorPolicyCount !== 3n || pendingEvaluatorPolicyCount !== 0n) throw new Error("DiligenceRoom evaluator admission set is not exactly three frozen recipes");
      if (evaluatorPolicySetRoot.toLowerCase() !== deployment.evaluatorPolicySetRoot.toLowerCase()) throw new Error("DiligenceRoom evaluator policy-set root does not match the release pin");
      if (evaluatorPoliciesApproved.some((approved) => !approved)) throw new Error("DiligenceRoom contains an inactive evaluator policy slot");
      const expectedEvaluatorPolicies = deployment.evaluatorPolicies
        .map((descriptor) => descriptor.policy_commitment.toLowerCase())
        .sort();
      const observedEvaluatorPolicies = evaluatorPolicies
        .map((commitment) => commitment.toLowerCase())
        .sort();
      if (
        expectedEvaluatorPolicies.length !== 3
        || observedEvaluatorPolicies.some((commitment, index) => commitment !== expectedEvaluatorPolicies[index])
      ) throw new Error("DiligenceRoom evaluator policies do not equal the release descriptor set");
      if (teeComposeHash.toLowerCase() !== composeHash) throw new Error("Configured TEE identity is not bound to the release compose hash");
      if (!composeApproved) throw new Error("Release compose hash is not approved on-chain");
      const policy: ContractWritePolicy = {
        bytecodeObserved: true,
        inspectedBlock: blockNumber,
        productionRelease: true,
        developer,
        initialDeveloper,
        releaseGovernanceController,
        pendingDeveloper: zeroAddress,
        pendingDeveloperActivatesAt: 0n,
        resultVerifier,
        resultVerifierFrozen: true,
        attestationVerifier,
        attestationReleasePolicyHash,
        attestationBindingFrozen: true,
        composeApprovalRequired: true,
        teeIdentityApprovalRequired: true,
        approvalRequirementsFrozen: true,
        composeAdditionsFrozen: true,
        teeIdentityAdditionsFrozen: true,
        feeBpsFrozen: true,
        computeSettlementPolicyEnabled: true,
        approvedComposeCount: 1n,
        approvedTeeIdentityCount: 1n,
        pendingComposeCount: 0n,
        pendingTeeIdentityCount: 0n,
        approvedEvaluatorPolicyCount: 3n,
        pendingEvaluatorPolicyCount: 0n,
        evaluatorPolicySetFrozen: true,
        evaluatorPolicySetRoot,
        evaluatorPolicies,
        teeComposeHash,
        composeApproved: true,
      };
      setWritePolicy(policy);
      setPolicyMessage(`Write gate matched at Base Sepolia block ${blockNumber}: the immutable governance controller accepted its delayed handoff, no developer transfer is pending, and the frozen release contains one compose, one TEE, and exactly three evaluator recipes.`);
      return policy;
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Contract write policy inspection failed";
      setPolicyMessage(message);
      if (expectedAccount) throw new Error(message);
      return undefined;
    }
  };

  const refreshPending = async (account: Address | undefined) => {
    setPendingNative(0n);
    setPendingUsdc(0n);
    if (!deployment.contractAddress || !account) return;
    try {
      const blockNumber = await publicClient.getBlockNumber();
      const [native, usdc] = await Promise.all([
        publicClient.readContract({
          address: deployment.contractAddress,
          abi: diligenceRoomAbi,
          functionName: "pendingWithdrawals",
          args: [zeroAddress, account],
          blockNumber,
        }),
        deployment.usdcAddress
          ? publicClient.readContract({
            address: deployment.contractAddress,
            abi: diligenceRoomAbi,
            functionName: "pendingWithdrawals",
            args: [deployment.usdcAddress, account],
            blockNumber,
          })
          : Promise.resolve(0n),
      ]);
      if (wallet.account()?.toLowerCase() !== account.toLowerCase()) return;
      setPendingNative(native);
      setPendingUsdc(usdc);
    } catch (cause) {
      setLoadError(cause instanceof Error ? cause.message : "Unable to read pending withdrawals");
    }
  };

  const refresh = async () => {
    if (!deployment.contractAddress) return;
    const generation = ++dealLoadGeneration;
    setChainBacked(false);
    setLoading(true);
    setLoadError("");
    setLoadFailure(undefined);
    try {
      try {
        const page = await loadDeals();
        if (generation !== dealLoadGeneration) return;
        setDeals([...page.deals]);
        setDealSnapshot(page.snapshot);
        setDealContinuation(page.continuation);
        setChainBacked(true);
      } catch (cause) {
        if (generation !== dealLoadGeneration) return;
        setLoadError(cause instanceof Error ? cause.message : "Unable to read the contract");
        setLoadFailure("restart");
      }
      await inspectContractWritePolicy();
    } finally {
      if (generation === dealLoadGeneration) setLoading(false);
    }
  };

  const loadMoreDeals = async () => {
    const cursor = dealContinuation();
    if (!cursor || loading()) return;
    const generation = dealLoadGeneration;
    setLoading(true);
    setLoadError("");
    setLoadFailure(undefined);
    try {
      const page = await loadDeals({ cursor });
      if (generation !== dealLoadGeneration || dealContinuation() !== cursor) return;
      setDeals((current) => [...mergeDealPages(current, page.deals)]);
      setDealSnapshot(page.snapshot);
      setDealContinuation(page.continuation);
    } catch (cause) {
      if (generation !== dealLoadGeneration) return;
      setLoadError(cause instanceof Error ? cause.message : "Unable to load the next pinned room page");
      setLoadFailure("more");
    } finally {
      if (generation === dealLoadGeneration) setLoading(false);
    }
  };

  const retryDealLoad = () => {
    if (loadFailure() === "more" && dealContinuation()) {
      void loadMoreDeals();
      return;
    }
    void refresh();
  };

  const inspectExactDeal = async () => {
    const candidate = exactDealId().trim();
    if (!/^(0|[1-9][0-9]*)$/.test(candidate)) {
      setExactLookupError("Enter one canonical nonnegative Deal Room ID");
      return;
    }
    const requestedId = BigInt(candidate);
    const generation = ++exactLookupGeneration;
    setExactLookupLoading(true);
    setExactLookupError("");
    try {
      const lookup = await loadDealById(requestedId);
      if (generation !== exactLookupGeneration || exactDealId().trim() !== candidate) return;
      setExactLookup(lookup);
    } catch (cause) {
      if (generation !== exactLookupGeneration) return;
      setExactLookup(undefined);
      setExactLookupError(cause instanceof Error ? cause.message : "Unable to inspect that exact Deal Room ID");
    } finally {
      if (generation === exactLookupGeneration) setExactLookupLoading(false);
    }
  };

  onMount(() => void refresh());
  createEffect(() => {
    const account = wallet.account();
    void refreshPending(account);
  });

  const filtered = createMemo(() => {
    const account = wallet.account()?.toLowerCase();
    const recoveryDealId = artifactUploadRecovery()?.dealId;
    return deals().filter((deal) => {
      if (deal.id.toString() === recoveryDealId) return true;
      if (filter() === "open") return deal.state === "Created" || deal.state === "Funded" || deal.state === "Evaluated";
      if (filter() === "settled") return TERMINAL.includes(deal.state);
      if (filter() === "mine") return Boolean(account && (deal.seller.toLowerCase() === account || deal.buyer.toLowerCase() === account));
      return true;
    });
  });
  const visibleDeals = createMemo(() => {
    const filteredDeals = filtered();
    const exact = exactLookup()?.deal;
    if (!exact || filteredDeals.some((deal) => deal.id === exact.id)) return filteredDeals;
    return [exact, ...filteredDeals];
  });

  const prepareArtifact = async (file: File | undefined) => {
    if (!creationDraftIsAllowed()) return;
    const request = ++artifactPreparation;
    setArtifactName("");
    setArtifactHash(undefined);
    setArtifactReceipt(undefined);
    setReceiptDownloaded(false);
    setArtifactError("");
    if (!file) return;
    if (file.size <= 0 || file.size > MAX_ARTIFACT_BYTES) {
      setArtifactError("Artifact must be between 1 byte and 1 MiB");
      return;
    }
    setHashing(true);
    setArtifactName(file.name);
    let bytes: Uint8Array | undefined;
    try {
      bytes = new Uint8Array(await file.arrayBuffer());
      if (request !== artifactPreparation || !creationDraftIsAllowed()) return;
      const receipt = createArtifactRecoveryReceipt(bytes);
      if (request !== artifactPreparation || !creationDraftIsAllowed()) return;
      setArtifactReceipt(receipt);
      setArtifactHash(receipt.artifact_commitment);
    } catch (cause) {
      if (request === artifactPreparation && creationDraftIsAllowed()) {
        setArtifactError(cause instanceof Error ? cause.message : "Could not prepare the artifact commitment");
        setArtifactName("");
      }
    } finally {
      bytes?.fill(0);
      if (request === artifactPreparation) setHashing(false);
    }
  };

  const downloadRecoveryReceipt = () => {
    if (!creationDraftIsAllowed()) return;
    const receipt = artifactReceipt();
    if (!receipt) return;
    const blob = new Blob([`${JSON.stringify(receipt, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `dnai-artifact-recovery-${receipt.artifact_commitment.slice(2, 14)}.json`;
    link.style.display = "none";
    document.body.append(link);
    try {
      link.click();
      setReceiptDownloaded(true);
    } finally {
      link.remove();
      URL.revokeObjectURL(url);
    }
  };

  const transact = async (
    label: string,
    action: (authorize: AuthorizeWrite) => Promise<Hex>,
    hooks?: TransactHooks,
  ): Promise<boolean> => {
    if (!draftMutationIsAllowed()) return false;
    if (!deployment.contractWritesEnabled || !deployment.contractAddress) {
      setTx({ kind: "error", label: policyMessage() || "Contract writes are not release-authorized in this build" });
      return false;
    }
    if (!wallet.account() || !wallet.client()) {
      setTx({ kind: "error", label: "Connect a wallet before starting a transaction" });
      return false;
    }
    const operation = await runDealRoomOperation(
      operationLock,
      "wallet_transaction",
      label,
      async (lease) => {
        let broadcastHash: Hex | undefined;
        let walletPromptOpened = false;
        try {
          if (!wallet.isCorrectChain()) await wallet.switchToBase();
          if (!operationLock.isCurrent(lease)) throw new Error("A newer Deal Room operation replaced this wallet request");
          const expectedAccount = wallet.account();
          const expectedClient = wallet.client();
          const contract = deployment.contractAddress;
          if (!expectedAccount || !expectedClient || !contract) throw new Error("Wallet or DiligenceRoom configuration changed before authorization");
          let authorizationCount = 0;
          const expectedContext = {
            account: expectedAccount,
            client: expectedClient,
            chainId: baseSepolia.id,
            authorizationVersion: wallet.authorizationVersion(),
          };
          const readContext = () => ({
            account: wallet.account(),
            client: wallet.client(),
            chainId: wallet.chainId(),
            authorizationVersion: wallet.authorizationVersion(),
          });
          const authorize: AuthorizeWrite = (prompt) => promptAfterFreshPolicy({
            expected: expectedContext,
            readContext,
            inspect: inspectContractWritePolicy,
            onPrompt: (policy) => {
              if (!operationLock.isCurrent(lease)) throw new Error("Wallet authorization lease is no longer current");
              authorizationCount += 1;
              walletPromptOpened = true;
              setTx({ kind: "wallet", label: `${label}: confirm in your wallet (policy checked at block ${policy.inspectedBlock})` });
            },
            prompt: ({ client, account, policy }) => prompt({ client, account, contract, policy }),
          });

          const hash = await action(authorize);
          broadcastHash = hash;
          // Retain the hash synchronously before receipt polling or any other
          // awaited operation can lose the wallet response.
          hooks?.onBroadcast?.(hash);
          if (!operationLock.isCurrent(lease)) throw new Error("Wallet authorization lease is no longer current");
          if (authorizationCount === 0) throw new Error("Mutation attempted without a fresh contract policy inspection");
          assertWalletMutationContext(
            readContext(),
            expectedContext,
            "Wallet account, provider, chain, or authorization changed while confirming the mutation",
          );
          setTx({ kind: "chain", label: `${label}: waiting for Base Sepolia`, hash });
          const receipt = await publicClient.waitForTransactionReceipt({ hash });
          if (!operationLock.isCurrent(lease)) throw new Error("Transaction confirmation lease is no longer current");
          if (receipt.status !== "success") throw new Error(`${label} reverted on Base Sepolia`);
          assertWalletMutationContext(
            readContext(),
            expectedContext,
            "Wallet account, provider, chain, or authorization changed before transaction confirmation",
          );
          setTx({ kind: "success", label: `${label} confirmed`, hash });
          await Promise.all([refresh(), refreshPending(expectedAccount), wallet.refreshBalance()]);
          return true;
        } catch (cause) {
          hooks?.onFailure?.(cause, broadcastHash, walletPromptOpened);
          setTx({
            kind: "error",
            label: cause instanceof Error ? cause.message : `${label} failed`,
            hash: broadcastHash,
          });
          return false;
        }
      },
    );
    return operation.started ? operation.value : false;
  };

  const finalizeCreatedDeal = async (
    result: DealCreationReconciliation,
  ): Promise<boolean> => {
    if (result.status !== "confirmed" || result.dealId === undefined || !result.transactionHash) {
      return false;
    }
    const privateReceiptUnavailable = creationRecoveryRestored() && artifactReceipt() === undefined;
    if (!clearDealCreationRecovery()) {
      setTx({
        kind: "error",
        label: "Room is confirmed, but the local recovery marker could not be cleared; retry remains locked",
        hash: result.transactionHash,
      });
      return false;
    }
    ++artifactPreparation;
    setArtifactReceipt(undefined);
    setArtifactHash(undefined);
    setArtifactName("");
    setReceiptDownloaded(false);
    setShowCreate(false);
    setExactDealId(result.dealId.toString());
    setTx({
      kind: "success",
      label: privateReceiptUnavailable
        ? `Room #${result.dealId.toString()} recovered. This reload did not restore private artifact material; use the recovery receipt you downloaded before broadcast.`
        : `Room #${result.dealId.toString()} matched its exact creation intent`,
      hash: result.transactionHash,
    });
    await refresh();
    return true;
  };

  const reconcileRetainedCreation = async (): Promise<DealCreationResolution | undefined> => {
    const recovery = dealCreationRecovery();
    if (!recovery || operationBusy()) return undefined;
    setTx({
      kind: "chain",
      label: recovery.transactionHash
        ? "Reconciling the retained transaction, exact DealCreated log, and room state"
        : "Scanning the bounded post-intent block range for one exact DealCreated log",
      hash: recovery.transactionHash,
    });
    try {
      const result = await reconcileDealCreation(recovery);
      if (result.transactionHash && !recovery.transactionHash) {
        persistDealCreationRecovery(
          createDealCreationRecovery(recovery.intent, result.transactionHash),
          false,
        );
      }
      setDealCreationResolution(result);
      if (result.status === "confirmed") {
        await finalizeCreatedDeal(result);
      } else {
        setTx({
          kind: result.status === "pending" ? "chain" : "error",
          label: result.reason,
          hash: result.transactionHash,
        });
      }
      return result;
    } catch (cause) {
      const label = cause instanceof Error ? cause.message : "Deal Room creation reconciliation failed";
      setTx({ kind: "error", label, hash: recovery.transactionHash });
      return undefined;
    }
  };

  const broadcastRetainedCreation = async (
    recovery: DealCreationRecovery,
    label: string,
  ): Promise<boolean> => {
    const intent = recovery.intent;
    const retainNotBroadcast = (reason: string): false => {
      const resolution = Object.freeze({
        status: "not_broadcast" as const,
        reason,
        observedThroughBlock: intent.startBlock,
      });
      setDealCreationResolution(resolution);
      setTx({ kind: "error", label: resolution.reason });
      return false;
    };
    try {
      if (!isZeroAddress(intent.paymentToken)) {
        if (!deployment.usdcAddress || !sameAddress(intent.paymentToken, deployment.usdcAddress)) {
          throw new Error("Retained creation payment token is not the release-approved USDC contract");
        }
        await assertApprovedUsdc(intent.paymentToken);
      }
    } catch (cause) {
      return retainNotBroadcast(
        cause instanceof Error
          ? `Creation stopped before a wallet prompt: ${cause.message}`
          : "Creation stopped before a wallet prompt",
      );
    }
    let failure: unknown;
    let walletPromptOpened = false;
    const created = await transact(
      label,
      async (authorize) => {
        // Detect account/chain/release/contract drift before the wallet prompt,
        // then repeat the exact check inside the freshly inspected callback.
        assertDealCreationIntentContext(intent, creationRuntimeContext());
        return authorize(({ client, account, contract }) => {
          assertDealCreationIntentContext(intent, {
            ...creationRuntimeContext(),
            account,
            contract,
          });
          if (isZeroAddress(intent.paymentToken)) {
            return client.writeContract({
              account,
              chain: baseSepolia,
              address: contract,
              abi: diligenceRoomAbi,
              functionName: "createDeal",
              args: [
                intent.reservePrice,
                intent.expiry,
                intent.artifactHash,
                intent.teeIdentity,
              ],
            });
          }
          return client.writeContract({
            account,
            chain: baseSepolia,
            address: contract,
            abi: diligenceRoomAbi,
            functionName: "createDeal",
            args: [
              intent.reservePrice,
              intent.expiry,
              intent.artifactHash,
              intent.teeIdentity,
              intent.paymentToken,
            ],
          });
        });
      },
      {
        onBroadcast: (transactionHash) => {
          persistDealCreationRecovery(
            createDealCreationRecovery(intent, transactionHash),
            false,
          );
        },
        onFailure: (cause, _hash, promptOpened) => {
          failure = cause;
          walletPromptOpened = promptOpened;
        },
      },
    );
    const retained = dealCreationRecovery();
    if (
      !created
      && !retained?.transactionHash
      && (!walletPromptOpened || walletRequestWasExplicitlyRejected(failure))
    ) {
      return retainNotBroadcast(
        walletRequestWasExplicitlyRejected(failure)
          ? "Wallet explicitly rejected the request before a transaction hash; the exact expiry and intent remain available for retry"
          : "Creation stopped before a wallet prompt; the exact expiry and intent remain available for retry",
      );
    }
    const resolution = await reconcileRetainedCreation();
    return resolution?.status === "confirmed";
  };

  const createDeal = async () => {
    if (!creationDraftIsAllowed()) return;
    const hash = artifactHash();
    const receipt = artifactReceipt();
    const tee = deployment.teeIdentity;
    const account = wallet.account();
    const contract = deployment.contractAddress;
    const releaseSha = deployment.releaseSha;
    const settlementAsset = settlement();
    const requestedReserve = reserve();
    const selectedPaymentToken = paymentToken();
    if (!wallet.client() || !account || !contract || !releaseSha || !hash || !receipt || !tee) {
      setTx({ kind: "error", label: "Connect a wallet and choose an artifact after the fresh deployment policy is configured" });
      return;
    }
    if (!receiptDownloaded()) {
      setTx({ kind: "error", label: "Download the private recovery receipt before creating the room" });
      return;
    }
    if (receipt.artifact_commitment !== hash || receipt.scheme !== ARTIFACT_COMMITMENT_SCHEME) {
      setTx({ kind: "error", label: "Artifact recovery receipt no longer matches the commitment" });
      return;
    }
    const days = Number(expiryDays());
    if (!Number.isSafeInteger(days) || days < 1 || days > 90) {
      setTx({ kind: "error", label: "Room lifetime must be a whole number from 1 to 90 days" });
      return;
    }
    try {
      const expiry = BigInt(Math.floor(Date.now() / 1000) + days * 86400);
      let reservePrice: bigint;
      let token: Address = zeroAddress;
      if (settlementAsset === "erc20") {
        if (!deployment.usdcAddress || !sameAddress(selectedPaymentToken, deployment.usdcAddress)) {
          throw new Error("Only the configured USDC contract is permitted by this frontend");
        }
        token = getAddress(selectedPaymentToken);
        const decimals = await assertApprovedUsdc(token);
        reservePrice = parseUnits(requestedReserve, decimals);
      } else {
        reservePrice = parseEther(requestedReserve);
      }
      if (reservePrice <= 0n) throw new Error("Reserve must be greater than zero");
      const intent = createDealCreationIntent({
        account,
        chainId: baseSepolia.id,
        releaseSha,
        contract,
        artifactHash: hash,
        reservePrice,
        expiry,
        teeIdentity: tee,
        paymentToken: token,
        startBlock: await publicClient.getBlockNumber(),
      });
      const recovery = createDealCreationRecovery(intent);
      // Persist the public, nonsecret exact intent before opening the wallet.
      // If this fails, no transaction prompt is issued.
      persistDealCreationRecovery(recovery, true);
      setDealCreationResolution(undefined);
      await broadcastRetainedCreation(recovery, "Create room");
    } catch (cause) {
      setTx({ kind: "error", label: cause instanceof Error ? cause.message : "Seller room intent is invalid" });
    }
  };

  const retryExactCreation = async () => {
    const recovery = dealCreationRecovery();
    if (!recovery || !creationRetryAllowed() || operationBusy()) return;
    if (recovery.intent.expiry <= BigInt(Math.floor(Date.now() / 1000))) {
      setTx({
        kind: "error",
        label: "The retained expiry has passed. Discard this resolved attempt explicitly before drafting a new expiry.",
        hash: recovery.transactionHash,
      });
      return;
    }
    try {
      assertDealCreationIntentContext(recovery.intent, creationRuntimeContext());
      const exactRetry = createDealCreationRecovery(recovery.intent);
      persistDealCreationRecovery(exactRetry, true);
      setDealCreationResolution(undefined);
      await broadcastRetainedCreation(exactRetry, "Retry exact room intent");
    } catch (cause) {
      setTx({ kind: "error", label: cause instanceof Error ? cause.message : "Exact room retry is blocked" });
    }
  };

  const discardResolvedCreation = () => {
    if (!creationRetryAllowed() || operationBusy()) return;
    if (clearDealCreationRecovery()) {
      setTx({
        kind: "idle",
        label: "",
      });
    }
  };

  const withdraw = async (token: Address = zeroAddress) => {
    if (!draftMutationIsAllowed()) return;
    if (!wallet.client() || !wallet.account() || !deployment.contractAddress) {
      setTx({ kind: "error", label: "Connect a wallet before withdrawing proceeds" });
      return;
    }
    if (isZeroAddress(token)) {
      await transact("Withdraw ETH proceeds", async (authorize) => {
        return authorize(({ client, account, contract }) => client.writeContract({ account, chain: baseSepolia, address: contract, abi: diligenceRoomAbi, functionName: "withdraw", args: [] }));
      });
      return;
    }
    await transact("Withdraw USDC proceeds", async (authorize) => {
      return authorize(({ client, account, contract }) => client.writeContract({ account, chain: baseSepolia, address: contract, abi: diligenceRoomAbi, functionName: "withdraw", args: [token] }));
    });
  };

  return (
    <div class="page-wrap product-page" aria-busy={mutationLocked()}>
      <header class="product-page-head">
        <div>
          <p class="overline">NDAI market · Base Sepolia</p>
          <h1>Attested deal rooms</h1>
          <p>Commit a private artifact, fund a hard cap, inspect only bounded findings, and settle without putting the secret on the public side.</p>
        </div>
        <button class="primary-button large" type="button" aria-describedby="deal-room-write-status" disabled={creationLocked()} onClick={() => {
          if (creationDraftIsAllowed()) setShowCreate(!showCreate());
        }}><Plus size={17} /> {dealCreationStorageError() ? "Recovery storage blocked" : dealCreationRecovery() ? "Creation recovery required" : writesReady() ? "Create room" : "Room creation locked"}</button>
      </header>

      <Show when={!contractConfigured()}>
        <div id="deal-room-write-status" class="environment-banner warning" role="status"><TriangleAlert size={17} /><div><strong>No fresh project-owned deployment</strong><span>No project-owned DiligenceRoom and CVM release is configured in this build. Any prior operator deployment is excluded rather than inherited. These modeled cards show the interaction shape only; writes remain locked, and no private artifact selector is enabled.</span></div></div>
      </Show>
      <Show when={contractConfigured()}>
        <div id="deal-room-write-status" class={`environment-banner ${writesReady() ? "live" : "warning"}`} role="status">
          {writesReady() ? <ShieldCheck size={17} /> : <LockKeyhole size={17} />}
          <div><strong>{writesReady()
            ? "Release write policy matched"
            : chainBacked()
              ? "Live chain read · writes locked"
              : loading()
                ? "Checking live chain read · writes locked"
                : "Chain read unavailable · writes locked"}</strong><span>{policyMessage() || "Inspecting runtime bytecode, roles, mandatory approval gates, compose binding, and TEE identity…"}</span></div>
        </div>
      </Show>

      <Show when={dealCreationStorageError()}>
        <div class="creation-recovery-storage-error" role="alert">
          <TriangleAlert size={17} />
          <div><strong>Local creation recovery is unavailable</strong><span>{dealCreationStorageError()}. Room creation stays locked because this browser cannot safely retain or clear an ambiguous broadcast.</span></div>
        </div>
      </Show>

      <Show when={dealCreationRecovery()} keyed>
        {(recovery) => (
          <section class="creation-recovery-panel" aria-label="Retained Deal Room creation recovery">
            <div class="creation-recovery-head">
              <div>
                <span class="step-index">RECOVERY</span>
                <h2>One exact room intent is retained</h2>
                <p>{dealCreationResolution()?.reason ?? "No retry is permitted until the browser reconciles the retained transaction or bounded DealCreated log range."}</p>
                <p class="creation-recovery-finality">Recovery clears only after {DEAL_CREATION_CONFIRMATION_DEPTH.toString()} canonical confirmations. This is a same-RPC depth check, not consensus finality.</p>
              </div>
              <span class={`status-badge ${dealCreationResolution()?.status === "confirmed" ? "success" : dealCreationResolution()?.status === "mismatch" ? "danger" : "gold"}`}>
                {dealCreationResolution()?.status ?? (recovery.transactionHash ? "hash retained" : "hash unavailable")}
              </span>
            </div>
            <dl class="creation-recovery-facts">
              <div><dt>Account</dt><dd><code>{shortAddress(recovery.intent.account, 8)}</code></dd></div>
              <div><dt>Reserve</dt><dd><strong>{formatAsset(recovery.intent.reservePrice, recovery.intent.paymentToken)}</strong></dd></div>
              <div><dt>Exact expiry</dt><dd><strong>{new Date(Number(recovery.intent.expiry) * 1000).toLocaleString()}</strong></dd></div>
              <div><dt>Start block</dt><dd><strong>{recovery.intent.startBlock.toString()}</strong></dd></div>
              <div><dt>Artifact commitment</dt><dd><code>{shortAddress(recovery.intent.artifactHash, 9)}</code></dd></div>
              <div><dt>Transaction</dt><dd><code>{recovery.transactionHash ? shortAddress(recovery.transactionHash, 9) : "No hash returned"}</code></dd></div>
            </dl>
            <Show when={creationRecoveryRestored()}>
              <p class="creation-recovery-limit"><FileKey size={14} /> Reload restored only public intent metadata. It did not store the private file, salt, recovery receipt, ciphertext, wallet credentials, or a tab-local no-broadcast classification. A hashless reload stays blocked unless one exact log appears.</p>
            </Show>
            <div class="creation-recovery-actions">
              <button class="secondary-button" type="button" disabled={operationBusy() || loading()} onClick={() => void reconcileRetainedCreation()}>
                <RefreshCw class={tx().kind === "chain" ? "spin" : ""} size={15} /> Reconcile exact intent
              </button>
              <Show when={creationRetryAllowed()}>
                <button class="primary-button" type="button" disabled={!writesReady() || operationBusy() || loading()} onClick={() => void retryExactCreation()}>
                  <FileKey size={15} /> Retry same expiry + intent
                </button>
                <button class="secondary-button danger" type="button" disabled={operationBusy() || loading()} onClick={discardResolvedCreation}>
                  <XCircle size={15} /> Discard resolved attempt
                </button>
              </Show>
            </div>
          </section>
        )}
      </Show>

      <Show when={pendingNative() > 0n || pendingUsdc() > 0n}>
        <div class="withdraw-stack">
          <Show when={pendingNative() > 0n}><div class="withdraw-banner"><HandCoins size={19} /><div><small>CLAIMABLE ETH PROCEEDS</small><strong>{formatEth(pendingNative())}</strong></div><button class="primary-button" type="button" disabled={!writesReady() || mutationLocked()} onClick={() => void withdraw()}>Withdraw ETH</button></div></Show>
          <Show when={pendingUsdc() > 0n && deployment.usdcAddress}><div class="withdraw-banner"><HandCoins size={19} /><div><small>CLAIMABLE USDC PROCEEDS</small><strong>{formatAsset(pendingUsdc(), deployment.usdcAddress as Address)}</strong></div><button class="primary-button" type="button" disabled={!writesReady() || mutationLocked()} onClick={() => void withdraw(deployment.usdcAddress as Address)}>Withdraw USDC</button></div></Show>
        </div>
      </Show>

      <Show when={showCreate()}>
        <section class="create-room-panel">
          <div class="create-room-intro">
            <span class="step-index">01</span>
            <h2>Create a private v2 commitment</h2>
            <p>The browser mixes 32 random secret bytes with the exact artifact before Ethereum keccak256. Only that salted, domain-separated commitment reaches Base Sepolia; this step never uploads the file.</p>
            <div class="privacy-note"><ShieldCheck size={16} /><span>Raw bytes stay in this browser. Temporary mutable buffers are zeroed best-effort; the private recovery receipt is never stored by this app.</span></div>
          </div>
          <form class="create-room-form" onSubmit={(event) => { event.preventDefault(); void createDeal(); }}>
            <label class="file-drop">
              <input type="file" disabled={creationLocked()} onChange={(event) => void prepareArtifact(event.currentTarget.files?.[0])} />
              <FileUp size={24} />
              <span><strong>{artifactName() || "Choose the private artifact"}</strong><small>{hashing() ? "Creating a salted commitment locally…" : "1 byte–1 MiB · no upload during commitment"}</small></span>
            </label>
            <Show when={artifactError()}><p class="ingress-result error" role="alert"><TriangleAlert size={13} />{artifactError()}</p></Show>
            <Show when={artifactHash()}>
              <div class="hash-preview"><Hash size={15} /><div><small>PUBLIC V2 COMMITMENT</small><code>{artifactHash()}</code></div></div>
              <div class="recovery-receipt-panel">
                <div><FileKey size={18} /><span><strong>Save the private recovery receipt</strong><small>It contains the secret needed to prove and encrypt this exact artifact later. Losing it makes upload impossible; do not share it publicly.</small></span></div>
                <button class={receiptDownloaded() ? "secondary-button" : "primary-button"} type="button" disabled={creationLocked()} onClick={downloadRecoveryReceipt}><Download size={16} /> {receiptDownloaded() ? "Receipt downloaded" : "Download recovery receipt"}</button>
              </div>
            </Show>
            <div class="form-grid two">
              <label><span>Seller reserve</span><div class="input-with-suffix"><input value={reserve()} inputmode="decimal" disabled={creationLocked()} onInput={(event) => {
                if (creationDraftIsAllowed()) setReserve(event.currentTarget.value);
              }} /><span>{settlement() === "erc20" ? "USDC" : "ETH"}</span></div></label>
              <label><span>Room lifetime</span><div class="input-with-suffix"><input value={expiryDays()} inputmode="numeric" disabled={creationLocked()} onInput={(event) => {
                if (creationDraftIsAllowed()) setExpiryDays(event.currentTarget.value);
              }} /><span>DAYS</span></div></label>
            </div>
            <div class="form-grid two">
              <label><span>Settlement asset</span><select value={settlement()} disabled={creationLocked()} onChange={(event) => {
                if (creationDraftIsAllowed()) setSettlement(event.currentTarget.value as "eth" | "erc20");
              }}><option value="eth">Native ETH</option><option value="erc20" disabled={!deployment.usdcAddress}>Approved USDC{deployment.usdcAddress ? "" : " · not configured"}</option></select></label>
              <Show when={settlement() === "erc20"} fallback={<label><span>Approved payment token</span><input value="Native ETH" readOnly aria-readonly="true" /></label>}>
                <label><span>Approved payment token</span><input value={paymentToken()} readOnly aria-readonly="true" /></label>
              </Show>
            </div>
            <label><span>Release-pinned TEE identity</span><input value={deployment.teeIdentity ?? "Not configured"} readOnly aria-readonly="true" /><small>Sellers cannot substitute an arbitrary signer. The write gate requires this identity to be approved and compose-bound on-chain.</small></label>
            <button class="primary-button large full" type="submit" disabled={creationLocked() || hashing() || !artifactHash() || !receiptDownloaded()}><FileKey size={17} /> Commit and create room <ArrowRight size={16} /></button>
            <Show when={artifactHash() && !receiptDownloaded()}><p class="modeled-note"><LockKeyhole size={13} /> Download the private recovery receipt to unlock room creation.</p></Show>
          </form>
        </section>
      </Show>

      <Show when={tx().kind !== "idle"}>
        <div class={`tx-toast ${tx().kind}`} role="status">
          <Show when={tx().kind === "wallet" || tx().kind === "chain"}><LoaderCircle class="spin" size={17} /></Show>
          <Show when={tx().kind === "success"}><CheckCircle2 size={17} /></Show>
          <Show when={tx().kind === "error"}><TriangleAlert size={17} /></Show>
          <span>{tx().label}</span>
          <Show when={tx().hash}><a href={explorerTx(tx().hash ?? "")} target="_blank" rel="noreferrer">Transaction <ExternalLink size={13} /></a></Show>
          <button type="button" aria-label="Dismiss transaction status" disabled={mutationLocked()} onClick={() => {
            if (draftMutationIsAllowed()) setTx({ kind: "idle", label: "" });
          }}>×</button>
        </div>
      </Show>

      <section class="deal-list-section">
        <h2 class="sr-only">Diligence rooms</h2>
        <div class="list-toolbar">
          <div class="filter-group" role="group" aria-label="Filter rooms">
            <Filter size={15} />
            <For each={[{ key: "all", label: "All rooms" }, { key: "open", label: "Active" }, { key: "mine", label: "My rooms" }, { key: "settled", label: "Resolved" }] as { key: DealFilter; label: string }[]}>
              {(item) => <button type="button" class={filter() === item.key ? "active" : ""} aria-pressed={filter() === item.key} disabled={mutationLocked()} onClick={() => {
                if (draftMutationIsAllowed()) setFilter(item.key);
              }}>{item.label}</button>}
            </For>
          </div>
          <div class="deal-list-actions">
            <form class="exact-deal-lookup" onSubmit={(event) => {
              event.preventDefault();
              void inspectExactDeal();
            }}>
              <Hash size={14} />
              <label class="sr-only" for="exact-deal-id">Inspect exact Deal Room ID</label>
              <input
                id="exact-deal-id"
                value={exactDealId()}
                inputmode="numeric"
                autocomplete="off"
                placeholder="Exact room ID"
                disabled={!contractConfigured() || exactLookupLoading()}
                onInput={(event) => {
                  setExactDealId(event.currentTarget.value);
                  setExactLookupError("");
                }}
              />
              <button class="secondary-button" type="submit" disabled={!contractConfigured() || exactLookupLoading()}>
                {exactLookupLoading() ? "Inspecting…" : "Inspect"}
              </button>
            </form>
            <button class="icon-text-button" type="button" onClick={() => {
              if (draftMutationIsAllowed()) void refresh();
            }} disabled={!contractConfigured() || loading() || mutationLocked()}><RefreshCw class={loading() ? "spin" : ""} size={15} /> Restart snapshot</button>
          </div>
        </div>

        <Show when={dealSnapshot()}>
          {(snapshot) => (
            <div class="deal-snapshot-status" role="status">
              <ShieldCheck size={14} />
              <span>
                <strong>{deals().length.toString()} of {snapshot().dealCount.toString()} snapshot rooms loaded</strong>
                All discovery pages remain pinned to Base Sepolia block {snapshot().blockNumber.toString()} · {shortAddress(snapshot().blockHash, 8)}.
              </span>
            </div>
          )}
        </Show>
        <Show when={filter() === "mine" && contractConfigured()}>
          <div class={`mine-scan-status ${dealContinuation() ? "partial" : "complete"}`} role="status">
            <WalletCards size={14} />
            <span>{!wallet.account()
              ? "Connect a wallet to evaluate ownership. No completeness claim is made without an account."
              : dealContinuation()
                ? "Partial ownership scan: My rooms covers only loaded pages. Load every older page before treating this result as complete."
                : dealSnapshot()
                  ? `Complete ownership scan for the snapshot at block ${dealSnapshot()!.blockNumber.toString()}.`
                  : "Ownership scan has not loaded a chain snapshot."}</span>
          </div>
        </Show>
        <Show when={exactLookup()}>
          {(lookup) => (
            <div class="exact-deal-result">
              <Hash size={14} />
              <span><strong>Exact room #{lookup().deal.id.toString()}</strong> independently read at block {lookup().snapshot.blockNumber.toString()} · {shortAddress(lookup().snapshot.blockHash, 8)} and shown once regardless of the active filter.</span>
              <button class="secondary-button" type="button" onClick={() => {
                ++exactLookupGeneration;
                setExactLookup(undefined);
                setExactDealId("");
                setExactLookupError("");
              }}>Clear exact lookup</button>
            </div>
          )}
        </Show>
        <Show when={exactLookupError()}><div class="inline-alert"><TriangleAlert size={16} />{exactLookupError()}</div></Show>
        <Show when={loadError()}>
          <div class="deal-page-error">
            <TriangleAlert size={16} />
            <span><strong>{loadFailure() === "more" ? "Pinned page failed" : "Snapshot restart failed"}</strong>{loadError()}</span>
            <button class="secondary-button" type="button" disabled={loading()} onClick={retryDealLoad}>
              <RefreshCw class={loading() ? "spin" : ""} size={14} /> {loadFailure() === "more" ? "Retry same page" : "Retry restart"}
            </button>
          </div>
        </Show>
        <div class="deal-grid">
          <For each={visibleDeals()}>{(deal) => <DealCard
            deal={deal}
            chainBacked={chainBacked()}
            writeReady={writesReady()}
            modeled={!contractConfigured()}
            inspectEvidence={props.inspectEvidence}
            transact={transact}
            operationLock={operationLock}
            operationBusy={operationBusy}
            mutationLocked={mutationLocked}
            artifactRecovery={() => artifactUploadRecovery()?.dealId === deal.id.toString() ? artifactUploadRecovery() : undefined}
            retainArtifactRecovery={retainArtifactRecovery}
            clearArtifactRecovery={clearArtifactRecovery}
          />}</For>
        </div>
        <Show when={!loading() && visibleDeals().length === 0}>
          <div class="empty-state"><CircleDollarSign size={28} /><h3>No rooms match this view</h3><p>Create the first room or switch filters.</p></div>
        </Show>
        <Show when={dealContinuation()}>
          <div class="deal-pagination-foot">
            <span>Older IDs remain outside this pinned view. Loading more will not advance the snapshot block.</span>
            <button class="secondary-button" type="button" disabled={loading()} onClick={() => void loadMoreDeals()}>
              <RefreshCw class={loading() ? "spin" : ""} size={14} /> {loadFailure() === "more" ? "Retry older page" : "Load older rooms"}
            </button>
          </div>
        </Show>
        <Show when={chainBacked() && dealSnapshot() && !dealContinuation()}>
          <div class="deal-pagination-complete"><CheckCircle2 size={14} /> All {dealSnapshot()!.dealCount.toString()} room IDs in the block {dealSnapshot()!.blockNumber.toString()} snapshot are loaded.</div>
        </Show>
      </section>
    </div>
  );
}
