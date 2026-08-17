import { describe, expect, it } from "vitest";
import { parseComputeVaultConfig } from "./computeVaultConfig";

const address = "0x1111111111111111111111111111111111111111";
const nativeProvider = "0x7777777777777777777777777777777777777777";
const erc20Provider = "0x8888888888888888888888888888888888888888";
const hash = `0x${"ab".repeat(32)}`;
const quotePin = `sha256:${"cd".repeat(32)}`;

describe("Compute vault release configuration", () => {
  it("stays inert when no vault release fields are present", () => {
    const config = parseComputeVaultConfig({});
    expect(config.fundingEnabled).toBe(false);
    expect(config.authorizationEnabled).toBe(false);
    expect(config.fundingConfigured).toBe(false);
    expect(config.authorizationConfigured).toBe(false);
    expect(config.issues).toEqual([]);
  });

  it("rejects raw funding unless the complete frozen release roots are configured", () => {
    const config = parseComputeVaultConfig({
      VITE_ENABLE_COMPUTE_VAULT_FUNDING: "true",
      VITE_COMPUTE_CREDIT_VAULT_ADDRESS: address,
      VITE_COMPUTE_CREDIT_VAULT_CODE_HASH: hash,
    });
    expect(config.fundingConfigured).toBe(false);
    expect(config.authorizationConfigured).toBe(false);
    expect(config.issues.join(" ")).toMatch(/METERING_POLICY_SET_HASH/);
    expect(config.issues.join(" ")).toMatch(/COMPUTE_METERING_VERIFIED_QUOTE_SHA256/);
    expect(config.issues.join(" ")).toMatch(/DEVELOPER_FEE_BPS/);
    expect(config.issues.join(" ")).toMatch(/NATIVE_PROVIDER/);
    expect(config.issues.join(" ")).toMatch(/complete release-pinned ERC20/);
  });

  it("keeps pinned raw funding available while incomplete authorization roots fail closed", () => {
    const config = parseComputeVaultConfig({
      VITE_ENABLE_COMPUTE_VAULT_FUNDING: "true",
      VITE_ENABLE_COMPUTE_VAULT_AUTHORIZATION: "true",
      VITE_COMPUTE_CREDIT_VAULT_ADDRESS: address,
      VITE_COMPUTE_CREDIT_VAULT_CODE_HASH: hash,
    });
    expect(config.fundingConfigured).toBe(false);
    expect(config.authorizationConfigured).toBe(false);
    expect(config.issues.join(" ")).toMatch(/METERING_VERIFIER/);
    expect(config.issues.join(" ")).toMatch(/METERING_POLICY_SET_HASH/);
    expect(config.issues.join(" ")).toMatch(/NATIVE_RATE_POLICY/);
    expect(config.issues.join(" ")).toMatch(/complete release-pinned ERC20/);
  });

  it("accepts only a complete exact execution and ERC20 binding", () => {
    const config = parseComputeVaultConfig({
      VITE_ENABLE_COMPUTE_VAULT_FUNDING: "true",
      VITE_ENABLE_COMPUTE_VAULT_AUTHORIZATION: "true",
      VITE_COMPUTE_CREDIT_VAULT_ADDRESS: address,
      VITE_COMPUTE_CREDIT_VAULT_CODE_HASH: hash,
      VITE_COMPUTE_VAULT_DEVELOPER: "0x2222222222222222222222222222222222222222",
      VITE_COMPUTE_VAULT_METERING_VERIFIER: "0x3333333333333333333333333333333333333333",
      VITE_COMPUTE_VAULT_METERING_QVL_VERIFIER: "0x6666666666666666666666666666666666666666",
      VITE_COMPUTE_VAULT_METERING_POLICY_SET_HASH: hash,
      VITE_COMPUTE_METERING_VERIFIED_QUOTE_SHA256: quotePin,
      VITE_COMPUTE_VAULT_DEVELOPER_FEE_BPS: "100",
      VITE_COMPUTE_VAULT_TEE_IDENTITY: "0x4444444444444444444444444444444444444444",
      VITE_COMPUTE_VAULT_COMPOSE_HASH: hash,
      VITE_COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT: hash,
      VITE_COMPUTE_VAULT_NATIVE_PROVIDER: nativeProvider,
      VITE_COMPUTE_VAULT_ERC20_ASSET_ADDRESS: "0x5555555555555555555555555555555555555555",
      VITE_COMPUTE_VAULT_ERC20_ASSET_CODE_HASH: hash,
      VITE_COMPUTE_VAULT_ERC20_SYMBOL: "usdc",
      VITE_COMPUTE_VAULT_ERC20_DECIMALS: "6",
      VITE_COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT: hash,
      VITE_COMPUTE_VAULT_ERC20_PROVIDER: erc20Provider,
    });
    expect(config.issues).toEqual([]);
    expect(config.authorizationConfigured).toBe(true);
    expect(config.token).toMatchObject({ symbol: "USDC", decimals: 6 });
    expect(config.meteringVerifiedQuoteSha256).toBe(quotePin);
    expect(config.developerFeeBps).toBe(100);
    expect(config.nativeRatePolicyProvider?.toLowerCase()).toBe(nativeProvider);
    expect(config.token?.ratePolicyProvider?.toLowerCase()).toBe(erc20Provider);
  });

  it("rejects an unpinned fee or collapsed rate-policy payout recipients", () => {
    const malformedFee = parseComputeVaultConfig({
      VITE_COMPUTE_VAULT_DEVELOPER_FEE_BPS: "2001",
    });
    expect(malformedFee.developerFeeBps).toBeUndefined();
    expect(malformedFee.issues.join(" ")).toMatch(/0 through 2000/);

    const collapsedProviders = parseComputeVaultConfig({
      VITE_COMPUTE_VAULT_NATIVE_PROVIDER: nativeProvider,
      VITE_COMPUTE_VAULT_ERC20_PROVIDER: nativeProvider,
    });
    expect(collapsedProviders.issues).toContain(
      "Compute vault native and ERC20 rate-policy providers must be distinct",
    );

    const zeroProvider = parseComputeVaultConfig({
      VITE_COMPUTE_VAULT_NATIVE_PROVIDER:
        "0x0000000000000000000000000000000000000000",
    });
    expect(zeroProvider.issues).toContain(
      "VITE_COMPUTE_VAULT_NATIVE_PROVIDER cannot be the zero address",
    );
  });

  it("requires distinct meter and metering-QVL release signers", () => {
    const config = parseComputeVaultConfig({
      VITE_COMPUTE_VAULT_METERING_VERIFIER: "0x3333333333333333333333333333333333333333",
      VITE_COMPUTE_VAULT_METERING_QVL_VERIFIER: "0x3333333333333333333333333333333333333333",
    });
    expect(config.issues).toContain("Compute vault meter and metering-QVL verifiers must be distinct");
  });

  it("rejects a malformed or uppercase metering verdict quote pin", () => {
    const config = parseComputeVaultConfig({
      VITE_COMPUTE_METERING_VERIFIED_QUOTE_SHA256: `sha256:${"AB".repeat(32)}`,
    });
    expect(config.meteringVerifiedQuoteSha256).toBeUndefined();
    expect(config.issues.join(" ")).toMatch(/64 lowercase hexadecimal/);
  });

  it("rejects partial token metadata, malformed booleans, and malformed addresses", () => {
    const partial = parseComputeVaultConfig({
      VITE_ENABLE_COMPUTE_VAULT_FUNDING: "yes",
      VITE_COMPUTE_CREDIT_VAULT_ADDRESS: "0x1234",
      VITE_COMPUTE_CREDIT_VAULT_CODE_HASH: hash,
      VITE_COMPUTE_VAULT_ERC20_SYMBOL: "USD COIN",
    });
    expect(partial.fundingEnabled).toBe(false);
    expect(partial.fundingConfigured).toBe(false);
    expect(partial.token).toBeUndefined();
    expect(partial.issues.join(" ")).toMatch(/exactly true or false/);
    expect(partial.issues.join(" ")).toMatch(/20-byte/);
    expect(partial.issues.join(" ")).toMatch(/ERC20_ASSET_ADDRESS/);
  });
});
