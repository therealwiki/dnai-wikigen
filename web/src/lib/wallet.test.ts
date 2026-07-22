import { beforeEach, describe, expect, it, vi } from "vitest";
import { stringToHex, type Address, type EIP1193Provider } from "viem";
import {
  buildApprovedWalletSigningMessage,
  injectedFallbackOptions,
  mergeWalletOptions,
  normalizeEip6963Announcement,
  requestPersonalSignature,
  requestWalletAuthSignature,
  switchProviderToBaseSepolia,
  validateSigningChallenge,
  validateWalletAuthSignature,
  wallet,
  type SigningChallengeResponse,
  type WalletOption,
} from "./wallet";

vi.mock("./contract", () => ({ publicClient: { getBalance: vi.fn(async () => 0n) } }));

const ACCOUNT_A = "0x1111111111111111111111111111111111111111" as Address;
const ACCOUNT_B = "0x2222222222222222222222222222222222222222" as Address;

interface MockProviderOptions {
  account?: Address;
  chainId?: number;
  ignoreListenerRemoval?: boolean;
  rejectAccounts?: number;
  switchBehavior?: "success" | "missing-then-add" | "wrapped-missing-then-add" | "reject";
}

function mockProvider(input: MockProviderOptions = {}) {
  let currentAccount = input.account ?? ACCOUNT_A;
  let currentChain = input.chainId ?? 84532;
  let switchCalls = 0;
  const listeners = new Map<string, Set<(value: unknown) => void>>();
  const request = vi.fn(async (args: { method: string; params?: readonly unknown[] | object }): Promise<unknown> => {
    if (args.method === "eth_requestAccounts") {
      if (input.rejectAccounts) throw { code: input.rejectAccounts, message: "provider supplied rejection text" };
      return [currentAccount];
    }
    if (args.method === "eth_accounts") return [currentAccount];
    if (args.method === "eth_chainId") return `0x${currentChain.toString(16)}`;
    if (args.method === "wallet_switchEthereumChain") {
      switchCalls += 1;
      if (input.switchBehavior === "reject") throw { code: 4001, message: "no" };
      if (input.switchBehavior === "missing-then-add" && switchCalls === 1) throw { code: 4902, message: "unknown chain" };
      if (input.switchBehavior === "wrapped-missing-then-add" && switchCalls === 1) {
        throw { code: -32603, data: { originalError: { code: 4902 } }, message: "wrapped unknown chain" };
      }
      currentChain = 84532;
      return null;
    }
    if (args.method === "wallet_addEthereumChain") return null;
    if (args.method === "personal_sign") return `0x${"ab".repeat(65)}`;
    throw { code: 4200, message: `unsupported ${args.method}` };
  });
  const provider = {
    request,
    on(event: string, listener: (value: unknown) => void) {
      const values = listeners.get(event) ?? new Set();
      values.add(listener);
      listeners.set(event, values);
    },
    removeListener(event: string, listener: (value: unknown) => void) {
      if (!input.ignoreListenerRemoval) listeners.get(event)?.delete(listener);
    },
  } as unknown as EIP1193Provider;
  return {
    provider,
    request,
    emit(event: string, value: unknown) {
      for (const listener of [...(listeners.get(event) ?? [])]) listener(value);
    },
    setAccount(value: Address) { currentAccount = value; },
    setChain(value: number) { currentChain = value; },
  };
}

function walletOption(provider: EIP1193Provider, overrides: Partial<WalletOption> = {}): WalletOption {
  return {
    info: {
      uuid: "350670db-19fa-4704-a166-e52e178b59d2",
      name: "Example Wallet",
      icon: "data:image/png;base64,AA==",
      rdns: "com.example.wallet",
    },
    provider,
    source: "eip6963",
    metadataWarning: false,
    ...overrides,
  };
}

beforeEach(() => {
  wallet.disconnect();
});

describe("wallet signing boundary", () => {
  it("requires the complete canonical message and rejects appended signing text", () => {
    const address = "0x1111111111111111111111111111111111111111" as Address;
    const issuedAt = Math.floor(Date.now() / 1000);
    const expiresAt = issuedAt + 300;
    const statement = "Authorize encrypted artifact upload for the specified diligence deal. This request will not trigger a blockchain transaction.";
    const resources = ["- urn:dnai:deal:42", "- urn:dnai:scope:artifact:upload"];
    const message = buildApprovedWalletSigningMessage({
      address,
      nonce: "0123456789abcdef0123456789abcdef",
      issuedAt,
      expiresAt,
      statement,
      resources,
    });
    const challenge: SigningChallengeResponse = {
      address,
      scope: "artifact:upload",
      nonce: "0123456789abcdef0123456789abcdef",
      issued_at: issuedAt,
      expires_at: expiresAt,
      message,
    };
    const expected = { address, scope: "artifact:upload", statement, resources, maximumTtlSeconds: 600 };
    expect(() => validateSigningChallenge(challenge, expected)).not.toThrow();
    expect(() => validateSigningChallenge({ ...challenge, message: `${message}\nAlso authorize an unrelated action.` }, expected))
      .toThrow(/exact approved signing request/);
    expect(() => validateSigningChallenge({
      ...challenge,
      address: null,
    } as unknown as SigningChallengeResponse, expected)).toThrow(/invalid wallet challenge/);
  });

  it("rejects stale and overlong challenge lifetimes before opening a wallet", () => {
    const address = "0x2222222222222222222222222222222222222222" as Address;
    const now = Math.floor(Date.now() / 1000);
    const statement = "Authorize access to the off-chain Compute Console. This signature will not trigger a blockchain transaction or transfer funds.";
    const resources = ["- urn:dnai:scope:compute:console"];
    const challenge: SigningChallengeResponse = {
      address,
      scope: "compute:console",
      nonce: "fedcba9876543210fedcba9876543210",
      issued_at: now - 700,
      expires_at: now + 100,
      message: "x".repeat(100),
    };
    expect(() => validateSigningChallenge(challenge, {
      address,
      scope: "compute:console",
      statement,
      resources,
      maximumTtlSeconds: 600,
    })).toThrow(/invalid wallet challenge/);
  });

  it("binds an Arena session to the exact submit and owner-read resources", () => {
    const address = "0x5555555555555555555555555555555555555555" as Address;
    const issuedAt = Math.floor(Date.now() / 1000);
    const expiresAt = issuedAt + 300;
    const statement = "Authorize encrypted candidate submissions and read only your bounded submission status for the specified Arena challenge version during this short session. This request will not trigger a blockchain transaction.";
    const resources = [
      "- urn:dnai:arena:challenge:synthetic-bio-assay-qc:version:1.0.0",
      "- urn:dnai:scope:challenge:submit",
      "- urn:dnai:scope:challenge:submissions:read",
    ];
    const message = buildApprovedWalletSigningMessage({
      address,
      nonce: "11111111111111111111111111111111",
      issuedAt,
      expiresAt,
      statement,
      resources,
    });
    const challenge: SigningChallengeResponse = {
      address,
      scope: "challenge:submit challenge:submissions:read",
      nonce: "11111111111111111111111111111111",
      issued_at: issuedAt,
      expires_at: expiresAt,
      message,
    };
    const expected = {
      address,
      scope: "challenge:submit challenge:submissions:read",
      statement,
      resources,
      maximumTtlSeconds: 600,
    };
    expect(() => validateSigningChallenge(challenge, expected)).not.toThrow();
    expect(() => validateSigningChallenge({
      ...challenge,
      scope: "challenge:submit",
    }, expected)).toThrow(/invalid wallet challenge/);
    expect(() => validateSigningChallenge({
      ...challenge,
      message: `${message}\n- urn:dnai:scope:compute:console`,
    }, expected)).toThrow(/exact approved signing request/);
  });

  it("uses direct EIP-1193 personal_sign with the exact UTF-8 approval message", async () => {
    const address = "0x3333333333333333333333333333333333333333" as Address;
    const message = "DNAI Wikigen execution policy approval\n{\"decision\":\"pass\"}";
    const signature = `0x${"ab".repeat(65)}`;
    const request = vi.fn(async () => signature);
    const provider = { request } as unknown as EIP1193Provider;

    await expect(requestPersonalSignature(provider, address, message)).resolves.toBe(signature);
    expect(request).toHaveBeenCalledOnce();
    expect(request).toHaveBeenCalledWith({
      method: "personal_sign",
      params: [stringToHex(message), address],
    });
  });

  it("rejects malformed personal_sign results and unbounded signing text", async () => {
    const address = "0x4444444444444444444444444444444444444444" as Address;
    const request = vi.fn(async () => "0x1234");
    const provider = { request } as unknown as EIP1193Provider;

    await expect(requestPersonalSignature(provider, address, "bounded approval\nmessage"))
      .rejects.toThrow(/invalid personal_sign signature/);
    await expect(requestPersonalSignature(provider, address, "approval\u0000message"))
      .rejects.toThrow(/bounded canonical string/);
    expect(request).toHaveBeenCalledOnce();
  });

  it("accepts bounded 65-byte EOA and longer Safe-style auth signatures", async () => {
    const address = "0x5555555555555555555555555555555555555555" as Address;
    const eoaSignature = `0x${"aB".repeat(65)}` as const;
    const safeStyleSignature = `0x${"Cd".repeat(195)}` as const;
    expect(validateWalletAuthSignature(eoaSignature)).toBe(eoaSignature);
    expect(validateWalletAuthSignature(safeStyleSignature)).toBe(safeStyleSignature);

    const request = vi.fn(async () => safeStyleSignature);
    const provider = { request } as unknown as EIP1193Provider;
    await expect(requestWalletAuthSignature(provider, address, "Bounded service login"))
      .resolves.toBe(safeStyleSignature);
    expect(request).toHaveBeenCalledWith({
      method: "personal_sign",
      params: [stringToHex("Bounded service login"), address],
    });
  });

  it("rejects empty, odd-length, non-hex, and oversized auth signatures", () => {
    const invalid = [
      "0x",
      "0x1",
      "0xzz",
      `0x${"ab".repeat(4097)}`,
    ];
    for (const signature of invalid) {
      expect(() => validateWalletAuthSignature(signature)).toThrow(
        /invalid bounded authentication signature/,
      );
    }
  });
});

describe("wallet provider discovery", () => {
  it("accepts conforming EIP-6963 metadata and rejects spoofing primitives", () => {
    const { provider } = mockProvider();
    const valid = {
      info: {
        uuid: "350670db-19fa-4704-a166-e52e178b59d2",
        name: "Example Wallet",
        icon: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'/>",
        rdns: "com.example.wallet",
      },
      provider,
    };
    expect(normalizeEip6963Announcement(valid)).toMatchObject({
      source: "eip6963",
      metadataWarning: false,
      info: { rdns: "com.example.wallet" },
    });
    expect(normalizeEip6963Announcement({
      ...valid,
      info: { ...valid.info, uuid: "not-a-uuid" },
    })).toBeUndefined();
    expect(normalizeEip6963Announcement({
      ...valid,
      info: { ...valid.info, name: "Meta\u202eMask" },
    })).toBeUndefined();
    expect(normalizeEip6963Announcement({
      ...valid,
      info: { ...valid.info, icon: "https://tracker.example/wallet.svg" },
    })).toBeUndefined();
    expect(normalizeEip6963Announcement({
      ...valid,
      info: { ...valid.info, rdns: "io..wallet" },
    })).toBeUndefined();
  });

  it("keeps distinct providers with colliding self-attested identities and marks both", () => {
    const first = walletOption(mockProvider().provider);
    const second = walletOption(mockProvider({ account: ACCOUNT_B }).provider);
    const merged = mergeWalletOptions(mergeWalletOptions([], first), second);
    expect(merged).toHaveLength(2);
    expect(merged.every((option) => option.metadataWarning)).toBe(true);
    expect(mergeWalletOptions(merged, second)).toHaveLength(2);
  });

  it("deduplicates exact provider objects and lets a valid EIP-6963 announcement replace its generic fallback", () => {
    const { provider } = mockProvider();
    const [fallback] = injectedFallbackOptions(provider);
    expect(fallback).toMatchObject({ source: "injected", info: { name: "Injected wallet" } });
    const announced = walletOption(provider);
    const merged = mergeWalletOptions([fallback], announced);
    expect(merged).toHaveLength(1);
    expect(merged[0]).toMatchObject({ source: "eip6963", info: { name: "Example Wallet" } });
    expect(mergeWalletOptions(merged, announced)).toHaveLength(1);
  });

  it("bounds and deduplicates a malformed legacy providers array", () => {
    const first = mockProvider().provider;
    const second = mockProvider({ account: ACCOUNT_B }).provider;
    const injected = Object.assign(first as object, { providers: [first, {}, second, first] });
    const fallback = injectedFallbackOptions(injected);
    expect(fallback).toHaveLength(2);
    expect(fallback.map((option) => option.info.name)).toEqual(["Injected wallet 1", "Injected wallet 2"]);
    expect(injectedFallbackOptions({ request: vi.fn(), providers: "spoofed" })).toEqual([]);
  });
});

describe("wallet connection lifecycle", () => {
  it("connects without switching, signing, or submitting any transaction", async () => {
    const provider = mockProvider({ chainId: 1 });
    await wallet.connect(walletOption(provider.provider));
    expect(wallet.account()).toBe(ACCOUNT_A);
    expect(wallet.chainId()).toBe(1);
    expect(wallet.isCorrectChain()).toBe(false);
    expect(provider.request.mock.calls.map(([args]) => args.method)).toEqual([
      "eth_requestAccounts",
      "eth_chainId",
      "eth_accounts",
      "eth_chainId",
    ]);
    expect(provider.request.mock.calls.some(([args]) => ["personal_sign", "wallet_switchEthereumChain", "eth_sendTransaction"].includes(args.method))).toBe(false);
  });

  it("rebuilds the wallet client and invalidates authorization on active account and chain changes", async () => {
    const provider = mockProvider();
    await wallet.connect(walletOption(provider.provider));
    const initialVersion = wallet.authorizationVersion();
    provider.setAccount(ACCOUNT_B);
    provider.emit("accountsChanged", [ACCOUNT_B]);
    expect(wallet.account()).toBe(ACCOUNT_B);
    expect(wallet.client()?.account?.address).toBe(ACCOUNT_B);
    expect(wallet.authorizationVersion()).toBe(initialVersion + 1);

    const accountVersion = wallet.authorizationVersion();
    provider.setChain(1);
    provider.emit("chainChanged", "0x1");
    expect(wallet.chainId()).toBe(1);
    expect(wallet.authorizationVersion()).toBe(accountVersion + 1);
    provider.emit("chainChanged", "0x1");
    expect(wallet.authorizationVersion()).toBe(accountVersion + 1);
  });

  it("ignores callbacks from a replaced provider even when removeListener is broken", async () => {
    const stale = mockProvider({ ignoreListenerRemoval: true });
    const current = mockProvider({ account: ACCOUNT_B });
    await wallet.connect(walletOption(stale.provider));
    await wallet.connect(walletOption(current.provider, {
      info: { ...walletOption(current.provider).info, uuid: "591f9d43-42ce-4e9c-b0d1-32f0e62a6e6d", name: "Current Wallet" },
    }));
    const version = wallet.authorizationVersion();
    stale.emit("accountsChanged", [ACCOUNT_A]);
    stale.emit("chainChanged", "0x1");
    stale.emit("disconnect", { code: 4900 });
    expect(wallet.account()).toBe(ACCOUNT_B);
    expect(wallet.chainId()).toBe(84532);
    expect(wallet.authorizationVersion()).toBe(version);
  });

  it("prevents a slower connection request from replacing a newer selected provider", async () => {
    const stale = mockProvider();
    const current = mockProvider({ account: ACCOUNT_B });
    const originalRequest = stale.request.getMockImplementation();
    let resolveAccounts: ((value: unknown) => void) | undefined;
    stale.request.mockImplementation(async (args: { method: string; params?: readonly unknown[] | object }) => {
      if (args.method === "eth_requestAccounts") {
        return await new Promise<unknown>((resolve) => { resolveAccounts = resolve; });
      }
      return await originalRequest?.(args);
    });
    const staleConnection = wallet.connect(walletOption(stale.provider));
    const staleRejected = expect(staleConnection).rejects.toThrow(/superseded/i);
    await vi.waitFor(() => expect(resolveAccounts).toBeTypeOf("function"));
    await wallet.connect(walletOption(current.provider, {
      info: { ...walletOption(current.provider).info, uuid: "591f9d43-42ce-4e9c-b0d1-32f0e62a6e6d", name: "Current Wallet" },
    }));
    resolveAccounts?.([ACCOUNT_A]);
    await staleRejected;
    expect(wallet.account()).toBe(ACCOUNT_B);
    expect(wallet.connectedName()).toBe("Current Wallet");
  });

  it("rejects a signature result if the active account changes while the wallet prompt is open", async () => {
    const provider = mockProvider();
    await wallet.connect(walletOption(provider.provider));
    const originalRequest = provider.request.getMockImplementation();
    let resolveSignature: ((value: unknown) => void) | undefined;
    provider.request.mockImplementation(async (args: { method: string; params?: readonly unknown[] | object }) => {
      if (args.method === "personal_sign") {
        return await new Promise<unknown>((resolve) => { resolveSignature = resolve; });
      }
      return await originalRequest?.(args);
    });
    const signing = wallet.signPersonalMessage("Bounded user-approved message");
    const rejected = expect(signing).rejects.toThrow(/account or chain changed/i);
    await vi.waitFor(() => expect(resolveSignature).toBeTypeOf("function"));
    provider.setAccount(ACCOUNT_B);
    provider.emit("accountsChanged", [ACCOUNT_B]);
    resolveSignature?.(`0x${"ab".repeat(65)}`);
    await rejected;
  });

  it("fails closed on malformed active events and on provider disconnect", async () => {
    const malformed = mockProvider();
    await wallet.connect(walletOption(malformed.provider));
    malformed.emit("accountsChanged", ["not-an-address"]);
    expect(wallet.account()).toBeUndefined();
    expect(wallet.error()).toMatch(/invalid account address/i);

    const disconnected = mockProvider();
    await wallet.connect(walletOption(disconnected.provider));
    disconnected.emit("disconnect", { code: 4900 });
    expect(wallet.account()).toBeUndefined();
    expect(wallet.error()).toMatch(/disconnected/i);
  });

  it("surfaces bounded user rejection and pending-request errors", async () => {
    const rejected = mockProvider({ rejectAccounts: 4001 });
    await expect(wallet.connect(walletOption(rejected.provider))).rejects.toThrow(/rejected in the wallet/i);
    expect(wallet.error()).toMatch(/rejected in the wallet/i);
    expect(wallet.account()).toBeUndefined();

    const pending = mockProvider({ rejectAccounts: -32002 });
    await expect(wallet.connect(walletOption(pending.provider))).rejects.toThrow(/already pending/i);
    expect(wallet.error()).toMatch(/already pending/i);

    const misleading = mockProvider();
    misleading.request.mockImplementationOnce(async () => {
      throw new Error(`Success\u202e${"x".repeat(300)}`);
    });
    await expect(wallet.connect(walletOption(misleading.provider))).rejects.toThrow(/^Wallet connection failed:/);
    expect(wallet.error()).not.toContain("\u202e");
    expect(wallet.error().length).toBeLessThanOrEqual(206);
  });

  it("adds Base Sepolia when absent, then explicitly switches and confirms chain 84532", async () => {
    const provider = mockProvider({ chainId: 1, switchBehavior: "missing-then-add" });
    await expect(switchProviderToBaseSepolia(provider.provider)).resolves.toBe(84532);
    const methods = provider.request.mock.calls.map(([args]) => args.method);
    expect(methods).toEqual([
      "wallet_switchEthereumChain",
      "wallet_addEthereumChain",
      "eth_chainId",
      "wallet_switchEthereumChain",
      "eth_chainId",
    ]);
    const addCall = provider.request.mock.calls.find(([args]) => args.method === "wallet_addEthereumChain")?.[0];
    expect(addCall?.params).toEqual([expect.objectContaining({
      chainId: "0x14a34",
      chainName: "Base Sepolia",
      rpcUrls: ["https://sepolia.base.org"],
      blockExplorerUrls: ["https://sepolia.basescan.org"],
    })]);
  });

  it("recognizes a wrapped unknown-chain error used by compatible injected wallets", async () => {
    const provider = mockProvider({ chainId: 1, switchBehavior: "wrapped-missing-then-add" });
    await expect(switchProviderToBaseSepolia(provider.provider)).resolves.toBe(84532);
    expect(provider.request.mock.calls.map(([args]) => args.method)).toContain("wallet_addEthereumChain");
  });

  it("does not hide a rejected Base Sepolia switch", async () => {
    const provider = mockProvider({ chainId: 1, switchBehavior: "reject" });
    await wallet.connect(walletOption(provider.provider));
    await expect(wallet.switchToBase()).rejects.toThrow(/rejected in the wallet/i);
    expect(wallet.chainId()).toBe(1);
    expect(wallet.error()).toMatch(/rejected in the wallet/i);
  });
});
