import {
  formatUnits,
  getAddress,
  keccak256,
  parseEventLogs,
  zeroAddress,
  type Address,
  type Hex,
} from "viem";
import { BASE_SEPOLIA, deployment } from "../config";
import { publicClient } from "./contract";
import { wallet } from "./wallet";

const NONZERO_BYTES32 = /^0x(?!0{64}$)[0-9a-fA-F]{64}$/;

export const royaltyDistributorAbi = [
  {
    type: "event",
    name: "RoyaltyWithdrawn",
    inputs: [
      { name: "owner", type: "address", indexed: true },
      { name: "token", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
  {
    type: "function",
    name: "pending",
    stateMutability: "view",
    inputs: [{ name: "token", type: "address" }, { name: "owner", type: "address" }],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function",
    name: "processedQueries",
    stateMutability: "view",
    inputs: [{ name: "distributor", type: "address" }, { name: "queryRef", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "withdraw",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    type: "function",
    name: "withdraw",
    stateMutability: "nonpayable",
    inputs: [{ name: "token", type: "address" }],
    outputs: [],
  },
] as const;

export type RoyaltyAssetKind = "native" | "usdc";

export interface RoyaltyReplayInspection {
  distributor: Address;
  queryRef: Hex;
  processed: boolean;
}

export interface RoyaltyRailState {
  address?: Address;
  configuredCodeHash?: Hex;
  runtimeCodeHash?: Hex;
  runtimeVerified: boolean;
  observedChainId?: number;
  blockNumber?: bigint;
  account?: Address;
  nativePending?: bigint;
  usdcPending?: bigint;
  usdcAddress?: Address;
  replay?: RoyaltyReplayInspection;
  issues: readonly string[];
}

function sameHex(left: string | undefined, right: string | undefined): boolean {
  return Boolean(left && right && left.toLowerCase() === right.toLowerCase());
}

function sameAddress(left: string | undefined, right: string | undefined): boolean {
  return Boolean(left && right && left.toLowerCase() === right.toLowerCase());
}

export function normalizeRoyaltyDistributor(value: string): Address {
  try {
    const normalized = getAddress(value.trim());
    if (sameAddress(normalized, zeroAddress)) throw new Error("zero caller");
    return normalized;
  } catch {
    throw new Error("Distributor must be one nonzero exact EVM address");
  }
}

export function normalizeRoyaltyQueryRef(value: string): Hex {
  const candidate = value.trim();
  if (!NONZERO_BYTES32.test(candidate)) {
    throw new Error("Query reference must be one exact nonzero bytes32 value");
  }
  return candidate.toLowerCase() as Hex;
}

export function formatRoyaltyAmount(value: bigint, decimals: number, maximumFractionDigits = 6): string {
  const [whole, fraction = ""] = formatUnits(value, decimals).split(".");
  const bounded = fraction.slice(0, Math.max(0, maximumFractionDigits)).replace(/0+$/, "");
  return bounded ? `${whole}.${bounded}` : whole;
}

export function assessRoyaltyRuntime(input: {
  address?: Address;
  configuredCodeHash?: Hex;
  observedCodeHash?: Hex;
  observedChainId?: number;
}): { verified: boolean; issues: readonly string[] } {
  const issues: string[] = [];
  if (!input.address) issues.push("RoyaltyDistributor address is not release configured");
  if (!input.configuredCodeHash) issues.push("RoyaltyDistributor runtime code hash is not release pinned");
  if (input.observedChainId === undefined) {
    issues.push("RoyaltyDistributor RPC chain has not been verified");
  } else if (input.observedChainId !== BASE_SEPOLIA.id) {
    issues.push(`RoyaltyDistributor RPC reported chain ${input.observedChainId}, not Base Sepolia ${BASE_SEPOLIA.id}`);
  }
  if (
    input.address
    && input.configuredCodeHash
    && input.observedChainId === BASE_SEPOLIA.id
    && !sameHex(input.configuredCodeHash, input.observedCodeHash)
  ) issues.push("Observed RoyaltyDistributor runtime does not match the release pin");
  return { verified: issues.length === 0, issues };
}

export async function loadRoyaltyRailState(
  account?: Address,
  replayInput?: { distributor: string; queryRef: string },
): Promise<RoyaltyRailState> {
  const address = deployment.royaltyDistributorAddress;
  const configuredCodeHash = deployment.royaltyDistributorCodeHash;
  const usdcAddress = deployment.usdcAddress;
  const initial = assessRoyaltyRuntime({ address, configuredCodeHash });
  if (!address || !configuredCodeHash) {
    return {
      address,
      configuredCodeHash,
      runtimeVerified: false,
      account,
      usdcAddress,
      issues: initial.issues,
    };
  }

  // The viem client is configured for Base Sepolia, but the remote endpoint is
  // still an external input. Confirm its reported chain before trusting a
  // block number, runtime, balance, or replay-domain read.
  const observedChainId = await publicClient.getChainId();
  if (observedChainId !== BASE_SEPOLIA.id) {
    const readiness = assessRoyaltyRuntime({ address, configuredCodeHash, observedChainId });
    return {
      address,
      configuredCodeHash,
      runtimeVerified: false,
      observedChainId,
      account,
      usdcAddress,
      issues: readiness.issues,
    };
  }

  const replay = replayInput
    ? {
      distributor: normalizeRoyaltyDistributor(replayInput.distributor),
      queryRef: normalizeRoyaltyQueryRef(replayInput.queryRef),
    }
    : undefined;
  const blockNumber = await publicClient.getBlockNumber();
  const runtime = await publicClient.getBytecode({ address, blockNumber });
  const runtimeCodeHash = runtime && runtime !== "0x" ? keccak256(runtime) : undefined;
  const readiness = assessRoyaltyRuntime({
    address,
    configuredCodeHash,
    observedCodeHash: runtimeCodeHash,
    observedChainId,
  });
  if (!readiness.verified) {
    return {
      address,
      configuredCodeHash,
      runtimeCodeHash,
      runtimeVerified: false,
      observedChainId,
      blockNumber,
      account,
      usdcAddress,
      issues: readiness.issues,
    };
  }

  const [nativePending, usdcPending, processed] = await Promise.all([
    account
      ? publicClient.readContract({
        address,
        abi: royaltyDistributorAbi,
        functionName: "pending",
        args: [zeroAddress, account],
        blockNumber,
      })
      : Promise.resolve(undefined),
    account && usdcAddress
      ? publicClient.readContract({
        address,
        abi: royaltyDistributorAbi,
        functionName: "pending",
        args: [usdcAddress, account],
        blockNumber,
      })
      : Promise.resolve(undefined),
    replay
      ? publicClient.readContract({
        address,
        abi: royaltyDistributorAbi,
        functionName: "processedQueries",
        args: [replay.distributor, replay.queryRef],
        blockNumber,
      })
      : Promise.resolve(undefined),
  ]);

  return {
    address,
    configuredCodeHash,
    runtimeCodeHash,
    runtimeVerified: true,
    observedChainId,
    blockNumber,
    account,
    nativePending,
    usdcPending,
    usdcAddress,
    replay: replay && processed !== undefined ? { ...replay, processed } : undefined,
    issues: [],
  };
}

async function royaltyWalletContext(): Promise<{
  account: Address;
  client: NonNullable<ReturnType<typeof wallet.client>>;
  authorizationVersion: number;
}> {
  if (!wallet.account() || !wallet.client()) throw new Error("Connect a wallet before claiming a royalty balance");
  if (!wallet.isCorrectChain()) await wallet.switchToBase();
  const account = wallet.account();
  const client = wallet.client();
  if (!account || !client || !wallet.isCorrectChain()) throw new Error("Wallet is not connected to Base Sepolia");
  return { account, client, authorizationVersion: wallet.authorizationVersion() };
}

function assertStableRoyaltyWallet(
  expectedAccount: Address,
  expectedClient: NonNullable<ReturnType<typeof wallet.client>>,
  expectedAuthorizationVersion: number,
): void {
  if (
    !wallet.isCorrectChain()
    || !sameAddress(wallet.account(), expectedAccount)
    || wallet.client() !== expectedClient
    || wallet.authorizationVersion() !== expectedAuthorizationVersion
  ) throw new Error("Wallet account, provider, or chain changed before royalty withdrawal");
}

export async function withdrawRoyaltyBalance(
  assetKind: RoyaltyAssetKind,
): Promise<{ hash: Hex; amount: bigint; symbol: "ETH" | "USDC"; decimals: 18 | 6 }> {
  const { account, client, authorizationVersion } = await royaltyWalletContext();
  const state = await loadRoyaltyRailState(account);
  if (!state.runtimeVerified || !state.address) {
    throw new Error(state.issues[0] ?? "Royalty withdrawal is not bound to a verified runtime");
  }
  const token = assetKind === "native" ? zeroAddress : state.usdcAddress;
  const amount = assetKind === "native" ? state.nativePending : state.usdcPending;
  const symbol = assetKind === "native" ? "ETH" : "USDC";
  const decimals = assetKind === "native" ? 18 : 6;
  if (!token) throw new Error("Canonical Base Sepolia USDC is not release configured");
  if (!amount || amount <= 0n) throw new Error(`No ${symbol} royalty balance is claimable by this wallet`);

  const simulation = assetKind === "native"
    ? await publicClient.simulateContract({
      account,
      address: state.address,
      abi: royaltyDistributorAbi,
      functionName: "withdraw",
      args: [],
    })
    : await publicClient.simulateContract({
      account,
      address: state.address,
      abi: royaltyDistributorAbi,
      functionName: "withdraw",
      args: [token],
    });
  assertStableRoyaltyWallet(account, client, authorizationVersion);
  const hash = await client.writeContract(simulation.request as never) as Hex;
  const receipt = await publicClient.waitForTransactionReceipt({ hash, confirmations: 2, timeout: 120_000 });
  if (receipt.status !== "success") throw new Error("Base Sepolia royalty withdrawal reverted");
  if (
    !sameHex(receipt.transactionHash, hash)
    || !sameAddress(receipt.from, account)
    || !sameAddress(receipt.to ?? undefined, state.address)
  ) throw new Error("Base Sepolia royalty withdrawal receipt did not match the submitted claim");
  const withdrawalEvents = parseEventLogs({
    abi: royaltyDistributorAbi,
    eventName: "RoyaltyWithdrawn",
    logs: receipt.logs,
    strict: true,
  }).filter((event) => (
    sameAddress(event.address, state.address)
    && sameAddress(event.args.owner, account)
    && sameAddress(event.args.token, token)
    && event.args.amount > 0n
  ));
  if (withdrawalEvents.length !== 1) {
    throw new Error("Base Sepolia receipt did not contain one exact royalty withdrawal event");
  }
  // A new distribution can land after the pinned balance read but before this
  // transaction. The contract withdraws the execution-time balance, so report
  // the authenticated event amount rather than the possibly older read.
  const withdrawnAmount = withdrawalEvents[0].args.amount;
  if (await publicClient.getChainId() !== BASE_SEPOLIA.id) {
    throw new Error("Royalty receipt RPC no longer reports Base Sepolia");
  }
  assertStableRoyaltyWallet(account, client, authorizationVersion);
  await wallet.refreshBalance(account);
  return { hash, amount: withdrawnAmount, symbol, decimals };
}
