import type { Address } from "viem";

export type WalletMutationContext<Client> = {
  account?: Address;
  client?: Client;
  chainId?: number;
  authorizationVersion?: number;
};

export type ExpectedWalletMutationContext<Client> = {
  account: Address;
  client: Client;
  chainId: number;
  authorizationVersion: number;
};

export function assertWalletMutationContext<Client>(
  current: WalletMutationContext<Client>,
  expected: ExpectedWalletMutationContext<Client>,
  message: string,
): void {
  if (
    current.account?.toLowerCase() !== expected.account.toLowerCase()
    || current.client !== expected.client
    || current.chainId !== expected.chainId
    || current.authorizationVersion !== expected.authorizationVersion
  ) throw new Error(message);
}

export async function promptAfterFreshPolicy<Client, Policy, Result>({
  expected,
  readContext,
  inspect,
  onPrompt,
  prompt,
}: {
  expected: ExpectedWalletMutationContext<Client>;
  readContext: () => WalletMutationContext<Client>;
  inspect: (expectedAccount: Address) => Promise<Policy | undefined>;
  onPrompt: (policy: Policy) => void;
  prompt: (authorized: ExpectedWalletMutationContext<Client> & { policy: Policy }) => Promise<Result>;
}): Promise<Result> {
  assertWalletMutationContext(
    readContext(),
    expected,
    "Wallet account, provider, chain, or authorization changed before the fresh contract policy inspection",
  );
  const policy = await inspect(expected.account);
  if (!policy) throw new Error("Contract policy inspection did not authorize this wallet prompt");
  assertWalletMutationContext(
    readContext(),
    expected,
    "Wallet account, provider, chain, or authorization drifted during the fresh contract policy inspection",
  );
  onPrompt(policy);
  return prompt({ ...expected, policy });
}
