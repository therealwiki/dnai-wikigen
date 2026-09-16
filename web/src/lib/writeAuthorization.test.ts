import { describe, expect, it, vi } from "vitest";
import type { Address } from "viem";
import {
  assertWalletMutationContext,
  promptAfterFreshPolicy,
  type WalletMutationContext,
} from "./writeAuthorization";

const ACCOUNT = "0x1111111111111111111111111111111111111111" as Address;
const OTHER_ACCOUNT = "0x2222222222222222222222222222222222222222" as Address;
const BASE_SEPOLIA_CHAIN_ID = 84_532;

describe("fresh wallet mutation authorization", () => {
  it("runs a fresh inspection immediately before each wallet prompt", async () => {
    const client = { id: "wallet-client" };
    const expected = { account: ACCOUNT, client, chainId: BASE_SEPOLIA_CHAIN_ID, authorizationVersion: 7 };
    const context: WalletMutationContext<typeof client> = { ...expected };
    const events: string[] = [];
    let inspection = 0;

    const authorize = () => promptAfterFreshPolicy({
      expected,
      readContext: () => context,
      inspect: async (account) => {
        inspection += 1;
        events.push(`inspect-${inspection}:${account}`);
        return { blockNumber: BigInt(100 + inspection) };
      },
      onPrompt: (policy) => events.push(`prompt-status:${policy.blockNumber}`),
      prompt: async () => {
        events.push(`wallet-prompt-${inspection}`);
        return `0x${inspection}`;
      },
    });

    expect(await authorize()).toBe("0x1");
    expect(await authorize()).toBe("0x2");
    expect(events).toEqual([
      `inspect-1:${ACCOUNT}`,
      "prompt-status:101",
      "wallet-prompt-1",
      `inspect-2:${ACCOUNT}`,
      "prompt-status:102",
      "wallet-prompt-2",
    ]);
  });

  it.each([
    ["account", { account: OTHER_ACCOUNT }],
    ["provider", { client: { id: "replacement-client" } }],
    ["chain", { chainId: 1 }],
    ["authorization", { authorizationVersion: 8 }],
  ])("fails closed when %s drifts during inspection", async (_label, drift) => {
    const client = { id: "wallet-client" };
    const expected = { account: ACCOUNT, client, chainId: BASE_SEPOLIA_CHAIN_ID, authorizationVersion: 7 };
    let context: WalletMutationContext<typeof client> = { ...expected };
    const prompt = vi.fn(async () => "0x1");

    await expect(promptAfterFreshPolicy({
      expected,
      readContext: () => context,
      inspect: async () => {
        context = { ...context, ...drift } as WalletMutationContext<typeof client>;
        return { blockNumber: 101n };
      },
      onPrompt: vi.fn(),
      prompt,
    })).rejects.toThrow(/drifted during the fresh contract policy inspection/);
    expect(prompt).not.toHaveBeenCalled();
  });

  it("rejects pre-existing drift before performing an inspection", async () => {
    const client = { id: "wallet-client" };
    const expected = { account: ACCOUNT, client, chainId: BASE_SEPOLIA_CHAIN_ID, authorizationVersion: 7 };
    const inspect = vi.fn(async () => ({ blockNumber: 101n }));

    await expect(promptAfterFreshPolicy({
      expected,
      readContext: () => ({ ...expected, chainId: 1 }),
      inspect,
      onPrompt: vi.fn(),
      prompt: vi.fn(async () => "0x1"),
    })).rejects.toThrow(/changed before the fresh contract policy inspection/);
    expect(inspect).not.toHaveBeenCalled();
  });

  it("asserts wallet context after a wallet prompt or receipt boundary", () => {
    const client = { id: "wallet-client" };
    const expected = { account: ACCOUNT, client, chainId: BASE_SEPOLIA_CHAIN_ID, authorizationVersion: 7 };
    expect(() => assertWalletMutationContext({ ...expected }, expected, "drifted")).not.toThrow();
    expect(() => assertWalletMutationContext({ ...expected, account: OTHER_ACCOUNT }, expected, "drifted"))
      .toThrow("drifted");
  });
});
