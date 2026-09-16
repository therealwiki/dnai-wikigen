import { describe, expect, it } from "vitest";
import { parseFrontendReleaseIdentity } from "./releaseIdentity";

describe("frontend release identity", () => {
  it("admits only an exact Git SHA into verification-chain provenance", () => {
    const sha = "a".repeat(40);
    expect(parseFrontendReleaseIdentity(sha)).toEqual({
      status: "release_bound",
      display: sha,
      releaseSha: sha,
      verificationChainReleaseSha: sha,
    });
  });

  it.each([undefined, "", "working-tree", "local-development", "a".repeat(39)])(
    "keeps %s explicitly modeled and outside verification claims",
    (value) => {
      const identity = parseFrontendReleaseIdentity(value);
      expect(identity.status).toBe("unconfigured_modeled");
      expect(identity.display).toBe("unconfigured · modeled");
      expect(identity.releaseSha).toBeUndefined();
      expect(identity.verificationChainReleaseSha).toBeUndefined();
    },
  );
});
