import { describe, expect, it } from "vitest";
import configSource from "./config.ts?raw";
import { deployment } from "./config";

describe("release-derived product feature gates", () => {
  it("defaults the dedicated Tinker customer and collaboration gates closed", () => {
    expect(deployment.tinkerCustomerEnabled).toBe(false);
    expect(deployment.collaborationEnabled).toBe(false);
  });

  it("parses each gate only from its own exact true marker", () => {
    expect(configSource).toContain(
      'tinkerCustomerEnabled: clean(env.VITE_ENABLE_TINKER_CUSTOMER) === "true"',
    );
    expect(configSource).toContain(
      'const collaborationFeatureEnabled = clean(env.VITE_ENABLE_COLLABORATION) === "true"',
    );
    expect(configSource).toContain(
      "collaborationEnabled: collaborationFeatureEnabled",
    );
    expect(configSource).not.toMatch(
      /tinkerCustomerEnabled:[^\n]*(?:COMPUTE_CONSOLE|COLLABORATION)/,
    );
    expect(configSource).not.toMatch(
      /collaborationEnabled:[^\n]*(?:COMPUTE_CONSOLE|TINKER_CUSTOMER)/,
    );
  });
});
