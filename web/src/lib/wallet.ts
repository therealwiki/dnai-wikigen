import { createSignal, onCleanup, onMount } from "solid-js";
import {
  createWalletClient,
  custom,
  getAddress,
  stringToHex,
  type Address,
  type EIP1193Provider,
  type Hex,
  type WalletClient,
} from "viem";
import { baseSepolia } from "viem/chains";
import { BASE_SEPOLIA, deployment } from "../config";
import { publicClient } from "./contract";

export interface WalletInfo {
  readonly uuid: string;
  readonly name: string;
  readonly icon: string;
  readonly rdns: string;
}

export type WalletDiscoverySource = "eip6963" | "injected";

export interface WalletOption {
  readonly info: WalletInfo;
  readonly provider: EIP1193Provider;
  readonly source: WalletDiscoverySource;
  /** EIP-6963 metadata is self-attested. A collision is a warning, never identity proof. */
  readonly metadataWarning: boolean;
}

interface ProviderAnnouncement extends CustomEvent<unknown> {
  readonly type: "eip6963:announceProvider";
}

declare global {
  interface Window {
    ethereum?: EIP1193Provider & { providers?: unknown };
  }
}

const [options, setOptions] = createSignal<WalletOption[]>([]);
const [discovering, setDiscovering] = createSignal(true);
const [account, setAccount] = createSignal<Address>();
const [chainId, setChainId] = createSignal<number>();
const [balance, setBalance] = createSignal<bigint>(0n);
const [connecting, setConnecting] = createSignal(false);
const [switchingChain, setSwitchingChain] = createSignal(false);
const [error, setError] = createSignal("");
const [sessionProof, setSessionProof] = createSignal("");
const [connectedName, setConnectedName] = createSignal("");
const [connectedSource, setConnectedSource] = createSignal<WalletDiscoverySource | "walletconnect">();
const [authorizationVersion, setAuthorizationVersion] = createSignal(0);

let activeProvider: EIP1193Provider | undefined;
let activeWalletClient: WalletClient | undefined;
let activeConnectorDisconnect: (() => Promise<void>) | undefined;
let providerGeneration = 0;
let connectionAttempt = 0;
let networkAttempt = 0;

type EventProvider = EIP1193Provider & {
  on: (event: string, listener: (value: unknown) => void) => void;
  removeListener: (event: string, listener: (value: unknown) => void) => void;
};

interface ProviderListenerBinding {
  readonly provider: EIP1193Provider;
  readonly generation: number;
  readonly accountsChanged: (value: unknown) => void;
  readonly chainChanged: (value: unknown) => void;
  readonly disconnected: (value: unknown) => void;
}

let activeListeners: ProviderListenerBinding | undefined;

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UNSAFE_DISPLAY_TEXT = /[\p{Cc}\p{Cf}]/u;
const MAX_DISCOVERED_PROVIDERS = 32;
const MAX_WALLET_AUTH_SIGNATURE_BYTES = 4096;

function isProvider(value: unknown): value is EIP1193Provider {
  try {
    if (!value || (typeof value !== "object" && typeof value !== "function")) return false;
    const candidate = value as { request?: unknown; on?: unknown; removeListener?: unknown };
    return typeof candidate.request === "function"
      && typeof candidate.on === "function"
      && typeof candidate.removeListener === "function";
  } catch {
    return false;
  }
}

function validRdns(value: string): boolean {
  if (value.length < 3 || value.length > 253 || value.startsWith(".") || value.endsWith(".")) return false;
  const labels = value.split(".");
  return labels.length >= 2 && labels.every((label) => (
    label.length >= 1
    && label.length <= 63
    && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
  ));
}

function validDataImage(value: string): boolean {
  return value.length > 0
    && value.length <= 96 * 1024
    && !/[\u0000-\u001f\u007f]/.test(value)
    && /^data:image\/[a-z0-9.+-]+(?:;[a-z0-9=+.-]+)*(?:;base64)?,/i.test(value);
}

/** Validate and copy untrusted EIP-6963 announcement metadata. */
export function normalizeEip6963Announcement(value: unknown): WalletOption | undefined {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
    const option = value as Record<string, unknown>;
    if (!option.info || typeof option.info !== "object" || Array.isArray(option.info)) return undefined;
    const info = option.info as Record<string, unknown>;
    const uuid = info.uuid;
    const name = info.name;
    const icon = info.icon;
    const rdns = info.rdns;
    if (
      typeof uuid !== "string"
      || !UUID_V4.test(uuid)
      || typeof name !== "string"
      || name.length < 1
      || name.length > 64
      || name.trim() !== name
      || UNSAFE_DISPLAY_TEXT.test(name)
      || typeof icon !== "string"
      || !validDataImage(icon)
      || typeof rdns !== "string"
      || !validRdns(rdns)
      || !isProvider(option.provider)
    ) return undefined;
    return {
      info: Object.freeze({ uuid: uuid.toLowerCase(), name, icon, rdns: rdns.toLowerCase() }),
      provider: option.provider,
      source: "eip6963",
      metadataWarning: false,
    };
  } catch {
    return undefined;
  }
}

function sameMetadata(left: WalletOption, right: WalletOption): boolean {
  return left.info.uuid === right.info.uuid
    && left.info.name === right.info.name
    && left.info.icon === right.info.icon
    && left.info.rdns === right.info.rdns;
}

function withCollisionWarnings(values: readonly WalletOption[]): WalletOption[] {
  return values.map((option, index) => ({
    ...option,
    metadataWarning: option.metadataWarning || values.some((other, otherIndex) => (
      index !== otherIndex
      && option.source === "eip6963"
      && other.source === "eip6963"
      && (
        option.info.uuid === other.info.uuid
        || option.info.rdns === other.info.rdns
        || option.info.name.toLowerCase() === other.info.name.toLowerCase()
      )
    )),
  }));
}

/**
 * Merge discovery results by provider object, not self-attested RDNS. Distinct
 * providers claiming the same UUID/RDNS stay selectable and are visibly marked.
 */
export function mergeWalletOptions(current: readonly WalletOption[], option: WalletOption): WalletOption[] {
  const existingIndex = current.findIndex((item) => item.provider === option.provider);
  if (existingIndex >= 0) {
    const existing = current[existingIndex];
    if (existing.source === "injected" && option.source === "eip6963") {
      const replaced = [...current];
      replaced[existingIndex] = option;
      return withCollisionWarnings(replaced);
    }
    if (sameMetadata(existing, option)) return [...current];
    const warned = [...current];
    warned[existingIndex] = { ...existing, metadataWarning: true };
    return withCollisionWarnings(warned);
  }
  if (current.length >= MAX_DISCOVERED_PROVIDERS) return [...current];
  return withCollisionWarnings([...current, option]);
}

/** Build generic, explicitly unverified fallback choices for legacy injection. */
export function injectedFallbackOptions(value: unknown): WalletOption[] {
  if (!value || (typeof value !== "object" && typeof value !== "function")) return [];
  let advertised: unknown;
  try {
    advertised = (value as EIP1193Provider & { providers?: unknown }).providers;
  } catch {
    advertised = undefined;
  }
  const candidates = Array.isArray(advertised) && advertised.length > 0 ? advertised : [value];
  const providers: EIP1193Provider[] = [];
  for (const candidate of candidates) {
    if (!isProvider(candidate) || providers.includes(candidate)) continue;
    providers.push(candidate);
    if (providers.length === 8) break;
  }
  return providers.map((provider, index) => ({
    info: Object.freeze({
      uuid: `injected-fallback-${index + 1}`,
      name: providers.length === 1 ? "Injected wallet" : `Injected wallet ${index + 1}`,
      icon: "",
      rdns: `injected.fallback.${index + 1}`,
    }),
    provider,
    source: "injected" as const,
    metadataWarning: false,
  }));
}

function addAnnouncedOption(value: unknown): boolean {
  const option = normalizeEip6963Announcement(value);
  if (!option) return false;
  setOptions((current) => mergeWalletOptions(current, option));
  setDiscovering(false);
  return true;
}

function invalidateAuthorization(): void {
  setSessionProof("");
  setAuthorizationVersion((current) => current + 1);
}

function parseChain(value: unknown, label: string): number {
  if (typeof value !== "string" || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value)) {
    throw new Error(`${label} returned a malformed chain identifier`);
  }
  const parsed = Number.parseInt(value, 16);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error(`${label} returned an unsupported chain identifier`);
  return parsed;
}

function parseAccounts(value: unknown, allowEmpty: boolean): Address[] {
  if (!Array.isArray(value) || value.length > 64 || value.some((item) => typeof item !== "string")) {
    throw new Error("Wallet returned a malformed account list");
  }
  if (!allowEmpty && value.length === 0) throw new Error("Wallet did not expose an account");
  try {
    return (value as string[]).map((item) => getAddress(item));
  } catch {
    throw new Error("Wallet returned an invalid account address");
  }
}

function providerErrorCodes(cause: unknown): number[] {
  const codes: number[] = [];
  try {
    if (!cause || typeof cause !== "object") return codes;
    const top = cause as { code?: unknown; data?: unknown };
    const candidates: unknown[] = [top.code, top.data];
    if (top.data && typeof top.data === "object") {
      const data = top.data as { code?: unknown; originalError?: unknown };
      candidates.push(data.code, data.originalError);
      if (data.originalError && typeof data.originalError === "object") {
        candidates.push((data.originalError as { code?: unknown }).code);
      }
    }
    for (const candidate of candidates) {
      if (typeof candidate !== "number" && typeof candidate !== "string") continue;
      const code = Number(candidate);
      if (Number.isInteger(code) && !codes.includes(code)) codes.push(code);
    }
  } catch {
    return codes;
  }
  return codes;
}

function userFacingProviderError(cause: unknown, action: string): Error {
  const codes = providerErrorCodes(cause);
  if (codes.includes(4001)) return new Error(`${action} was rejected in the wallet`);
  if (codes.includes(-32002)) return new Error("A wallet request is already pending; finish or reject it in the wallet first");
  if (codes.includes(4100)) return new Error(`${action} is not authorized for this site`);
  if (codes.includes(4200) || codes.includes(-32601)) return new Error(`This wallet does not support ${action.toLowerCase()}`);
  if (codes.includes(4900) || codes.includes(4901)) return new Error("The wallet is disconnected from its network; reconnect and try again");
  const message = cause instanceof Error
    ? cause.message.replace(/[\p{Cc}\p{Cf}]/gu, " ").replace(/\s+/g, " ").trim().slice(0, 180)
    : "";
  return new Error(message ? `${action} failed: ${message}` : `${action} failed`);
}

function createConnectedClient(provider: EIP1193Provider, nextAccount: Address): WalletClient {
  return createWalletClient({
    account: nextAccount,
    chain: baseSepolia,
    transport: custom(provider),
  });
}

function detachProviderEvents(): void {
  const binding = activeListeners;
  activeListeners = undefined;
  if (!binding) return;
  const events = binding.provider as EventProvider;
  try {
    events.removeListener("accountsChanged", binding.accountsChanged);
    events.removeListener("chainChanged", binding.chainChanged);
    events.removeListener("disconnect", binding.disconnected);
  } catch {
    // Generation checks below still make callbacks from a broken emitter inert.
  }
}

function clearActiveConnection(message = "", disconnectConnector = false): void {
  connectionAttempt += 1;
  networkAttempt += 1;
  providerGeneration += 1;
  const connectorDisconnect = activeConnectorDisconnect;
  detachProviderEvents();
  activeProvider = undefined;
  activeWalletClient = undefined;
  activeConnectorDisconnect = undefined;
  setAccount(undefined);
  setChainId(undefined);
  setBalance(0n);
  setConnectedName("");
  setConnectedSource(undefined);
  setConnecting(false);
  setSwitchingChain(false);
  invalidateAuthorization();
  setError(message);
  if (disconnectConnector && connectorDisconnect) void connectorDisconnect().catch(() => undefined);
}

function failActiveConnection(message: string): void {
  clearActiveConnection(message, true);
}

function attachProviderEvents(provider: EIP1193Provider, generation: number): void {
  const isCurrent = (): boolean => activeProvider === provider
    && activeListeners?.generation === generation
    && providerGeneration === generation;
  const accountsChanged = (next: unknown): void => {
    if (!isCurrent()) return;
    let values: Address[];
    try {
      values = parseAccounts(next, true);
    } catch (cause) {
      failActiveConnection(cause instanceof Error ? `${cause.message}; reconnect before continuing` : "Wallet emitted a malformed account update");
      return;
    }
    if (!values[0]) {
      failActiveConnection("The wallet no longer exposes an account; reconnect before continuing");
      return;
    }
    if (account()?.toLowerCase() === values[0].toLowerCase()) return;
    activeWalletClient = createConnectedClient(provider, values[0]);
    setAccount(values[0]);
    setError("");
    invalidateAuthorization();
    void refreshBalance(values[0]);
  };
  const chainChanged = (next: unknown): void => {
    if (!isCurrent()) return;
    let value: number;
    try {
      value = parseChain(next, "Wallet");
    } catch (cause) {
      failActiveConnection(cause instanceof Error ? `${cause.message}; reconnect before continuing` : "Wallet emitted a malformed chain update");
      return;
    }
    if (chainId() === value) return;
    setChainId(value);
    setError("");
    invalidateAuthorization();
  };
  const disconnected = (): void => {
    if (isCurrent()) failActiveConnection("Wallet disconnected; reconnect before continuing");
  };
  const binding: ProviderListenerBinding = { provider, generation, accountsChanged, chainChanged, disconnected };
  activeListeners = binding;
  const events = provider as EventProvider;
  try {
    events.on("accountsChanged", accountsChanged);
    events.on("chainChanged", chainChanged);
    events.on("disconnect", disconnected);
  } catch {
    detachProviderEvents();
    throw new Error("Wallet does not provide reliable account, network, and disconnect events");
  }
}

async function refreshBalance(nextAccount = account()): Promise<void> {
  if (!nextAccount) return;
  try {
    const nextBalance = await publicClient.getBalance({ address: nextAccount });
    if (account()?.toLowerCase() === nextAccount.toLowerCase()) setBalance(nextBalance);
  } catch {
    if (account()?.toLowerCase() === nextAccount.toLowerCase()) setBalance(0n);
  }
}

async function readChain(provider: EIP1193Provider): Promise<number> {
  return parseChain(await provider.request({ method: "eth_chainId" }), "Wallet");
}

function approvedBaseSepoliaRpcUrl(): string {
  let parsed: URL;
  try {
    parsed = new URL(BASE_SEPOLIA.rpcUrl);
  } catch {
    throw new Error("Base Sepolia RPC URL is malformed; the network cannot be added safely");
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw new Error("Base Sepolia network addition requires a credential-free HTTPS RPC URL");
  }
  return parsed.toString().replace(/\/$/, "");
}

/** Perform the explicit EIP-1193 switch/add/switch flow without touching app state. */
export async function switchProviderToBaseSepolia(provider: EIP1193Provider): Promise<number> {
  try {
    await provider.request({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: BASE_SEPOLIA.hexId }],
    });
  } catch (cause) {
    if (!providerErrorCodes(cause).includes(4902)) throw cause;
    await provider.request({
      method: "wallet_addEthereumChain",
      params: [
        {
          chainId: BASE_SEPOLIA.hexId,
          chainName: BASE_SEPOLIA.name,
          nativeCurrency: BASE_SEPOLIA.currency,
          rpcUrls: [approvedBaseSepoliaRpcUrl()],
          blockExplorerUrls: [BASE_SEPOLIA.explorerUrl],
        },
      ],
    });
    if (await readChain(provider) !== BASE_SEPOLIA.id) {
      await provider.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: BASE_SEPOLIA.hexId }],
      });
    }
  }
  const confirmedChain = await readChain(provider);
  if (confirmedChain !== BASE_SEPOLIA.id) throw new Error("Wallet did not switch to Base Sepolia");
  return confirmedChain;
}

async function switchToBase(): Promise<void> {
  const provider = activeProvider;
  const expectedAccount = account();
  if (!provider || !expectedAccount) throw new Error("Connect a wallet first");
  const attempt = ++networkAttempt;
  setSwitchingChain(true);
  setError("");
  try {
    const previousChain = chainId();
    const confirmedChain = await switchProviderToBaseSepolia(provider);
    if (attempt !== networkAttempt || activeProvider !== provider || account()?.toLowerCase() !== expectedAccount.toLowerCase()) {
      throw new Error("Wallet connection changed while switching networks");
    }
    setChainId(confirmedChain);
    if (previousChain !== confirmedChain) invalidateAuthorization();
  } catch (cause) {
    const normalized = userFacingProviderError(cause, "Base Sepolia network switch");
    if (attempt === networkAttempt) setError(normalized.message);
    throw normalized;
  } finally {
    if (attempt === networkAttempt) setSwitchingChain(false);
  }
}

async function requestPersonalSignResult(
  provider: EIP1193Provider,
  address: Address | string,
  message: string,
): Promise<unknown> {
  let normalizedAddress: Address;
  try {
    normalizedAddress = getAddress(address);
  } catch {
    throw new Error("Connected wallet address is invalid");
  }
  if (
    typeof message !== "string"
    || message.length === 0
    || new TextEncoder().encode(message).byteLength > 4096
    || /[\u0000-\u0009\u000b-\u001f\u007f]/.test(message)
  ) {
    throw new Error("Wallet approval message is not a bounded canonical string");
  }
  const response = await provider.request({
    method: "personal_sign",
    params: [stringToHex(message), normalizedAddress],
  });
  return response;
}

/**
 * Validate the contract-defined signature bytes returned for Deal, Arena, or
 * Compute authentication. EIP-1271 signatures are not necessarily 65 bytes,
 * but they remain strict, non-empty, even-length hex with a 4 KiB byte cap.
 */
export function validateWalletAuthSignature(response: unknown): Hex {
  if (typeof response !== "string" || !response.startsWith("0x")) {
    throw new Error("Wallet returned an invalid bounded authentication signature");
  }
  const rawHex = response.slice(2);
  if (
    rawHex.length === 0
    || rawHex.length > MAX_WALLET_AUTH_SIGNATURE_BYTES * 2
    || rawHex.length % 2 !== 0
    || !/^[0-9a-fA-F]+$/.test(rawHex)
  ) {
    throw new Error("Wallet returned an invalid bounded authentication signature");
  }
  return response as Hex;
}

/**
 * Ask an EIP-1193 wallet for a bounded Deal/Arena/Compute authentication
 * signature. The backend decides EOA versus EIP-1271 from its trusted Base
 * Sepolia RPC; the browser neither guesses account type nor supplies an RPC.
 */
export async function requestWalletAuthSignature(
  provider: EIP1193Provider,
  address: Address | string,
  message: string,
): Promise<Hex> {
  return validateWalletAuthSignature(
    await requestPersonalSignResult(provider, address, message),
  );
}

/**
 * Ask an EIP-1193 wallet for an exact recoverable EOA signature. Execution
 * policy and other EOA-only paths use this stricter boundary intentionally.
 */
export async function requestPersonalSignature(
  provider: EIP1193Provider,
  address: Address | string,
  message: string,
): Promise<Hex> {
  const response = await requestPersonalSignResult(provider, address, message);
  if (typeof response !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(response)) {
    throw new Error("Wallet returned an invalid personal_sign signature");
  }
  return response as Hex;
}

async function signPersonalMessage(message: string): Promise<Hex> {
  if (!activeProvider || !account()) throw new Error("Connect an EIP-1193 wallet before approving policy");
  if (chainId() !== BASE_SEPOLIA.id) await switchToBase();
  const provider = activeProvider;
  const expectedAccount = account();
  const expectedVersion = authorizationVersion();
  if (!provider || !expectedAccount) throw new Error("Wallet connection changed before policy approval");
  let signature: Hex;
  try {
    signature = await requestPersonalSignature(provider, expectedAccount, message);
  } catch (cause) {
    const normalized = userFacingProviderError(cause, "Wallet approval signature");
    setError(normalized.message);
    throw normalized;
  }
  if (
    activeProvider !== provider
    || account()?.toLowerCase() !== expectedAccount.toLowerCase()
    || chainId() !== BASE_SEPOLIA.id
    || authorizationVersion() !== expectedVersion
  ) {
    throw new Error("Wallet account or chain changed during policy approval");
  }
  return signature;
}

interface PreparedConnection {
  readonly account: Address;
  readonly chainId: number;
}

async function prepareConnection(provider: EIP1193Provider): Promise<PreparedConnection> {
  const response = await provider.request({ method: "eth_requestAccounts" });
  const requestedAccounts = parseAccounts(response, false);
  const firstChain = await readChain(provider);
  const confirmedAccounts = parseAccounts(await provider.request({ method: "eth_accounts" }), false);
  const confirmedChain = await readChain(provider);
  if (requestedAccounts[0].toLowerCase() !== confirmedAccounts[0].toLowerCase() || firstChain !== confirmedChain) {
    throw new Error("Wallet account or network changed while connecting; try again");
  }
  return { account: confirmedAccounts[0], chainId: confirmedChain };
}

async function attachProvider(
  provider: EIP1193Provider,
  name: string,
  source: WalletDiscoverySource | "walletconnect",
  attempt: number,
  connectorDisconnect?: () => Promise<void>,
): Promise<void> {
  if (!isProvider(provider)) throw new Error("Wallet does not implement the required EIP-1193 event interface");
  const prepared = await prepareConnection(provider);
  if (attempt !== connectionAttempt) throw new Error("Wallet connection was superseded by a newer request");
  const previousConnectorDisconnect = activeConnectorDisconnect;
  detachProviderEvents();
  providerGeneration += 1;
  activeProvider = provider;
  activeWalletClient = createConnectedClient(provider, prepared.account);
  activeConnectorDisconnect = connectorDisconnect;
  setConnectedName(name);
  setConnectedSource(source);
  setChainId(prepared.chainId);
  setAccount(prepared.account);
  try {
    attachProviderEvents(provider, providerGeneration);
  } catch (cause) {
    clearActiveConnection(cause instanceof Error ? cause.message : "Wallet event subscription failed", true);
    throw cause;
  }
  if (activeProvider !== provider || !activeWalletClient || !account()) {
    throw new Error(error() || "Wallet disconnected while connecting");
  }
  setError("");
  invalidateAuthorization();
  if (previousConnectorDisconnect && previousConnectorDisconnect !== connectorDisconnect) {
    void previousConnectorDisconnect().catch(() => undefined);
  }
  await refreshBalance(prepared.account);
}

async function connect(option: WalletOption): Promise<void> {
  const attempt = ++connectionAttempt;
  invalidateAuthorization();
  setConnecting(true);
  setError("");
  try {
    const source = option.source === "eip6963" ? "eip6963" : "injected";
    const reportedName = typeof option.info?.name === "string"
      && option.info.name.length >= 1
      && option.info.name.length <= 64
      && option.info.name.trim() === option.info.name
      && !UNSAFE_DISPLAY_TEXT.test(option.info.name)
      ? option.info.name
      : source === "eip6963" ? "Announced wallet" : "Injected wallet";
    await attachProvider(option.provider, reportedName, source, attempt);
  } catch (cause) {
    const normalized = userFacingProviderError(cause, "Wallet connection");
    if (attempt === connectionAttempt) setError(normalized.message);
    throw normalized;
  } finally {
    if (attempt === connectionAttempt) setConnecting(false);
  }
}

async function connectWalletConnect(): Promise<void> {
  if (!deployment.walletConnectProjectId) {
    throw new Error("WalletConnect is not configured for this deployment");
  }
  const attempt = ++connectionAttempt;
  invalidateAuthorization();
  setConnecting(true);
  setError("");
  let cleanup: (() => Promise<void>) | undefined;
  try {
    const { default: EthereumProvider } = await import("@walletconnect/ethereum-provider");
    const provider = await EthereumProvider.init({
      projectId: deployment.walletConnectProjectId,
      chains: [BASE_SEPOLIA.id],
      showQrModal: true,
      qrModalOptions: {
        // Keep the modal on the app's bundled font stack. Without an explicit
        // family AppKit preloads fonts.reown.com, which is intentionally not in
        // the production font-src policy.
        themeVariables: { "--wcm-font-family": "Manrope, system-ui, sans-serif" },
      },
      metadata: {
        name: "Wikigen",
        description: "Attested diligence rooms for private intelligence",
        url: window.location.origin,
        icons: [`${window.location.origin}/favicon.svg`],
      },
    });
    let disconnected = false;
    cleanup = async () => {
      if (disconnected) return;
      disconnected = true;
      await provider.disconnect();
    };
    await provider.connect();
    await attachProvider(provider as EIP1193Provider, "WalletConnect", "walletconnect", attempt, cleanup);
  } catch (cause) {
    if (cleanup && activeConnectorDisconnect !== cleanup) void cleanup().catch(() => undefined);
    const normalized = userFacingProviderError(cause, "WalletConnect connection");
    if (attempt === connectionAttempt) setError(normalized.message);
    throw normalized;
  } finally {
    if (attempt === connectionAttempt) setConnecting(false);
  }
}

export interface SigningChallengeResponse {
  address: string;
  scope: string;
  nonce: string;
  message: string;
  issued_at: number;
  expires_at: number;
}

interface WalletChallengeResponse extends SigningChallengeResponse {
  deal_id: string;
}

interface WalletTokenResponse {
  access_token: string;
  token_type: string;
  address: string;
  deal_id: string;
  scopes: string[];
  issued_at: number;
  expires_at: number;
}

export interface ComputeWalletTokenResponse {
  access_token: string;
  token_type: "Bearer";
  address: string;
  scopes: string[];
  issued_at: number;
  expires_at: number;
}

export interface ArenaWalletTokenResponse {
  access_token: string;
  token_type: "Bearer";
  address: string;
  challenge_id: string;
  challenge_version: string;
  scopes: ["challenge:submit", "challenge:submissions:read"];
  issued_at: number;
  expires_at: number;
}

interface ArenaWalletChallengeResponse extends SigningChallengeResponse {
  challenge_id: string;
  challenge_version: string;
  scope: "challenge:submit challenge:submissions:read";
  issued_at: number;
  expires_at: number;
}

interface ComputeWalletChallengeResponse {
  address: string;
  nonce: string;
  message: string;
  issued_at: number;
  expires_at: number;
  scope: "compute:console";
  chain_id: 84532;
}

async function responseJson<T>(response: Response): Promise<T> {
  const maxBytes = 32 * 1024;
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("application/json")) throw new Error("Delegate did not return application/json");
  const declaredLength = Number(response.headers.get("content-length") ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) throw new Error("Delegate wallet response exceeded 32 KiB");
  if (!response.body) throw new Error("Delegate returned an empty wallet response");
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let body = "";
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new Error("Delegate wallet response exceeded 32 KiB");
      }
      body += decoder.decode(value, { stream: true });
    }
    body += decoder.decode();
  } finally {
    reader.releaseLock();
  }
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch {
    value = undefined;
  }
  if (!response.ok) {
    const rawDetail = value && typeof value === "object" && "detail" in value
      ? String((value as { detail: unknown }).detail)
      : `Request failed with status ${response.status}`;
    const detail = rawDetail.replace(/[\p{Cc}\p{Cf}]/gu, " ").replace(/\s+/g, " ").trim().slice(0, 240);
    throw new Error(detail || `Request failed with status ${response.status}`);
  }
  if (value === undefined) throw new Error("Delegate returned malformed wallet JSON");
  return value as T;
}

export function buildApprovedWalletSigningMessage(input: {
  address: Address;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  statement: string;
  resources: string[];
}): string {
  return (
    `${deployment.walletAuthDomain} wants you to sign in with your Ethereum account:\n`
    + `${input.address.toLowerCase()}\n\n`
    + `${input.statement}\n\n`
    + `URI: ${deployment.walletAuthUri}\n`
    + "Version: 1\n"
    + `Chain ID: ${BASE_SEPOLIA.id}\n`
    + `Nonce: ${input.nonce}\n`
    + `Issued At: ${input.issuedAt}\n`
    + `Expiration Time: ${input.expiresAt}\n`
    + "Resources:\n"
    + input.resources.join("\n")
  );
}

export function validateSigningChallenge(
  challenge: SigningChallengeResponse,
  expected: {
    address: Address;
    scope: string;
    statement: string;
    resources: string[];
    maximumTtlSeconds: number;
  },
): void {
  const now = Math.floor(Date.now() / 1000);
  if (
    !challenge
    || typeof challenge !== "object"
    || typeof challenge.address !== "string"
    || !/^0x[0-9a-fA-F]{40}$/.test(challenge.address)
    || typeof challenge.scope !== "string"
    || typeof challenge.nonce !== "string"
    || !/^[0-9a-f]{32}$/.test(challenge.nonce)
    || typeof challenge.message !== "string"
    || challenge.message.length < 80
    || challenge.message.length > 4096
    || challenge.address.toLowerCase() !== expected.address.toLowerCase()
    || challenge.scope !== expected.scope
    || !Number.isInteger(challenge.issued_at)
    || challenge.issued_at > now + 30
    || challenge.issued_at < now - expected.maximumTtlSeconds - 30
    || !Number.isInteger(challenge.expires_at)
    || challenge.expires_at <= now
    || challenge.expires_at <= challenge.issued_at
    || challenge.expires_at - challenge.issued_at > expected.maximumTtlSeconds
  ) {
    throw new Error("Delegate returned an invalid wallet challenge");
  }
  const expectedMessage = buildApprovedWalletSigningMessage({
    address: expected.address,
    nonce: challenge.nonce,
    issuedAt: challenge.issued_at,
    expiresAt: challenge.expires_at,
    statement: expected.statement,
    resources: expected.resources,
  });
  if (challenge.message !== expectedMessage) throw new Error("Delegate wallet challenge is not the exact approved signing request");
}

function validateWalletToken(
  token: { access_token: string; token_type: string; address: string; scopes: string[]; issued_at: number; expires_at: number },
  expectedAddress: Address,
  expectedScope: string | readonly string[],
): void {
  const now = Math.floor(Date.now() / 1000);
  const expectedScopes = typeof expectedScope === "string" ? [expectedScope] : [...expectedScope];
  if (
    !token
    || typeof token !== "object"
    || token.token_type !== "Bearer"
    || typeof token.address !== "string"
    || !/^0x[0-9a-fA-F]{40}$/.test(token.address)
    || !Array.isArray(token.scopes)
    || token.scopes.some((scope) => typeof scope !== "string")
    || typeof token.access_token !== "string"
    || token.address.toLowerCase() !== expectedAddress.toLowerCase()
    || token.scopes.length !== expectedScopes.length
    || token.scopes.some((scope, index) => scope !== expectedScopes[index])
    || !Number.isInteger(token.issued_at)
    || token.issued_at > now + 30
    || token.issued_at < now - 930
    || !Number.isInteger(token.expires_at)
    || token.expires_at <= now
    || token.expires_at <= token.issued_at
    || token.expires_at - token.issued_at > 900
    || token.access_token.length < 80
    || token.access_token.length > 4096
    || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token.access_token)
  ) throw new Error("Delegate returned an invalid wallet-scoped token");
}

interface WalletAuthorizationContext {
  readonly provider: EIP1193Provider;
  readonly address: Address;
  readonly version: number;
}

async function walletAuthorizationContext(): Promise<WalletAuthorizationContext> {
  if (connecting()) throw new Error("Finish the active wallet connection request before authorizing a service");
  if (!activeProvider || !activeWalletClient || !account()) throw new Error("Connect a wallet first");
  if (chainId() !== BASE_SEPOLIA.id) await switchToBase();
  const provider = activeProvider;
  const address = account();
  if (!provider || !activeWalletClient || !address || chainId() !== BASE_SEPOLIA.id) {
    throw new Error("Wallet connection changed before authorization");
  }
  return { provider, address, version: authorizationVersion() };
}

function assertWalletAuthorizationContext(context: WalletAuthorizationContext): void {
  if (
    activeProvider !== context.provider
    || !activeWalletClient
    || account()?.toLowerCase() !== context.address.toLowerCase()
    || chainId() !== BASE_SEPOLIA.id
    || authorizationVersion() !== context.version
  ) throw new Error("Wallet account, network, or provider changed during authorization; start again");
}

async function signAuthorizationMessage(context: WalletAuthorizationContext, message: string): Promise<Hex> {
  assertWalletAuthorizationContext(context);
  let signature: Hex;
  try {
    signature = await requestWalletAuthSignature(context.provider, context.address, message);
  } catch (cause) {
    const normalized = userFacingProviderError(cause, "Wallet authorization signature");
    setError(normalized.message);
    throw normalized;
  }
  assertWalletAuthorizationContext(context);
  return signature;
}

async function authorizeDealUpload(dealId: bigint | string): Promise<WalletTokenResponse> {
  if (!deployment.delegateUrl) throw new Error("Fresh delegate endpoint is not configured");
  const context = await walletAuthorizationContext();
  const baseUrl = deployment.delegateUrl.replace(/\/$/, "");
  const challenge = await responseJson<WalletChallengeResponse>(await fetch(`${baseUrl}/auth/wallet/challenge`, {
    method: "POST",
    credentials: "omit",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: context.address, deal_id: String(dealId) }),
    signal: AbortSignal.timeout(10_000),
  }));
  if (challenge.deal_id !== String(dealId)) throw new Error("Wallet challenge is bound to a different deal");
  validateSigningChallenge(challenge, {
    address: context.address,
    scope: "artifact:upload",
    statement: "Authorize encrypted artifact upload for the specified diligence deal. This request will not trigger a blockchain transaction.",
    resources: [`- urn:dnai:deal:${String(dealId)}`, "- urn:dnai:scope:artifact:upload"],
    maximumTtlSeconds: 600,
  });
  const signature = await signAuthorizationMessage(context, challenge.message);
  const token = await responseJson<WalletTokenResponse>(await fetch(`${baseUrl}/auth/wallet/token`, {
    method: "POST",
    credentials: "omit",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ nonce: challenge.nonce, signature }),
    signal: AbortSignal.timeout(10_000),
  }));
  assertWalletAuthorizationContext(context);
  validateWalletToken(token, context.address, "artifact:upload");
  if (token.deal_id !== String(dealId)) throw new Error("Delegate returned a token outside the requested deal scope");
  setSessionProof(`deal ${String(dealId)} · artifact upload`);
  return token;
}

async function authorizeComputeConsole(): Promise<ComputeWalletTokenResponse> {
  if (!deployment.computeConsoleEnabled) throw new Error("Fresh Compute Console is not enabled for this deployment");
  if (!deployment.delegateUrl) throw new Error("Fresh delegate endpoint is not configured");
  const context = await walletAuthorizationContext();
  const expectedAddress = context.address;
  const baseUrl = deployment.delegateUrl.replace(/\/$/, "");
  const challenge = await responseJson<ComputeWalletChallengeResponse>(await fetch(`${baseUrl}/auth/compute/challenge`, {
    method: "POST",
    credentials: "omit",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: expectedAddress }),
    signal: AbortSignal.timeout(10_000),
  }));
  if (challenge.chain_id !== BASE_SEPOLIA.id) throw new Error("Compute challenge is not bound to Base Sepolia");
  validateSigningChallenge(challenge, {
    address: expectedAddress,
    scope: "compute:console",
    statement: "Authorize access to the off-chain Compute Console. This signature will not trigger a blockchain transaction or transfer funds.",
    resources: ["- urn:dnai:scope:compute:console"],
    maximumTtlSeconds: 600,
  });
  const signature = await signAuthorizationMessage(context, challenge.message);
  const token = await responseJson<ComputeWalletTokenResponse>(await fetch(`${baseUrl}/auth/compute/token`, {
    method: "POST",
    credentials: "omit",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ nonce: challenge.nonce, signature }),
    signal: AbortSignal.timeout(10_000),
  }));
  assertWalletAuthorizationContext(context);
  validateWalletToken(token, expectedAddress, "compute:console");
  setSessionProof("Compute Console · wallet scoped");
  return token;
}

async function authorizeArenaSession(challengeId: string, challengeVersion: string): Promise<ArenaWalletTokenResponse> {
  if (!deployment.delegateUrl) throw new Error("Fresh delegate endpoint is not configured");
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(challengeId) || !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(challengeVersion)) {
    throw new Error("Arena challenge version is malformed");
  }
  const context = await walletAuthorizationContext();
  const expectedAddress = context.address;
  const baseUrl = deployment.delegateUrl.replace(/\/$/, "");
  const challenge = await responseJson<ArenaWalletChallengeResponse>(await fetch(`${baseUrl}/auth/arena/challenge`, {
    method: "POST",
    credentials: "omit",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: expectedAddress, challenge_id: challengeId, challenge_version: challengeVersion }),
    signal: AbortSignal.timeout(10_000),
  }));
  if (challenge.challenge_id !== challengeId || challenge.challenge_version !== challengeVersion) {
    throw new Error("Arena challenge is bound to a different challenge version");
  }
  validateSigningChallenge(challenge, {
    address: expectedAddress,
    scope: "challenge:submit challenge:submissions:read",
    statement: "Authorize encrypted candidate submissions and read only your bounded submission status for the specified Arena challenge version during this short session. This request will not trigger a blockchain transaction.",
    resources: [
      `- urn:dnai:arena:challenge:${challengeId}:version:${challengeVersion}`,
      "- urn:dnai:scope:challenge:submit",
      "- urn:dnai:scope:challenge:submissions:read",
    ],
    maximumTtlSeconds: 600,
  });
  const signature = await signAuthorizationMessage(context, challenge.message);
  const token = await responseJson<ArenaWalletTokenResponse>(await fetch(`${baseUrl}/auth/arena/token`, {
    method: "POST",
    credentials: "omit",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ nonce: challenge.nonce, signature }),
    signal: AbortSignal.timeout(10_000),
  }));
  assertWalletAuthorizationContext(context);
  validateWalletToken(token, expectedAddress, ["challenge:submit", "challenge:submissions:read"]);
  if (token.challenge_id !== challengeId || token.challenge_version !== challengeVersion) throw new Error("Delegate returned a token for a different Arena challenge version");
  setSessionProof(`${challengeId} ${challengeVersion} · submit + my status`);
  return token;
}

function disconnect(): void {
  clearActiveConnection("", true);
}

function useWalletDiscovery(): void {
  onMount(() => {
    setOptions([]);
    setDiscovering(true);
    const announce = (event: Event): void => {
      if (!("detail" in event)) return;
      addAnnouncedOption((event as ProviderAnnouncement).detail);
    };
    window.addEventListener("eip6963:announceProvider", announce);
    window.dispatchEvent(new Event("eip6963:requestProvider"));
    const fallbackTimer = window.setTimeout(() => {
      if (options().length === 0) {
        for (const option of injectedFallbackOptions(window.ethereum)) {
          setOptions((current) => mergeWalletOptions(current, option));
        }
      }
      setDiscovering(false);
    }, 200);

    onCleanup(() => {
      window.clearTimeout(fallbackTimer);
      window.removeEventListener("eip6963:announceProvider", announce);
      if (activeProvider) clearActiveConnection("", true);
    });
  });
}

export const wallet = {
  options,
  discovering,
  account,
  chainId,
  balance,
  connecting,
  switchingChain,
  error,
  sessionProof,
  authorizationVersion,
  connectedName,
  connectedSource,
  client: () => activeWalletClient,
  provider: () => activeProvider,
  isCorrectChain: () => chainId() === BASE_SEPOLIA.id,
  connect,
  connectWalletConnect,
  switchToBase,
  authorizeDealUpload,
  authorizeComputeConsole,
  authorizeArenaSession,
  authorizeArenaSubmission: authorizeArenaSession,
  signPersonalMessage,
  disconnect,
  clearError: () => setError(""),
  refreshBalance,
  useDiscovery: useWalletDiscovery,
};
