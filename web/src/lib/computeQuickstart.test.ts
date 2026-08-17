import { describe, expect, it } from "vitest";
import { computeCredentialQuickstart } from "./computeQuickstart";

describe("Compute credential quickstart", () => {
  it("builds one secret-free, non-mutating jobs-read request", () => {
    const snippet = computeCredentialQuickstart({
      delegateUrl: "https://delegate.wikigen.example/",
      projectId: "project_123",
    });

    expect(snippet).toContain("WIKIGEN_API_URL='https://delegate.wikigen.example'");
    expect(snippet).toContain("WIKIGEN_PROJECT_ID='project_123'");
    expect(snippet).toContain("<paste-the-one-time-token-here>");
    expect(snippet).toContain("/compute/projects/${WIKIGEN_PROJECT_ID}/jobs");
    expect(snippet).not.toMatch(/POST|Idempotency-Key|jobs:create|job dispatch/i);
  });

  it("allows loopback HTTP for local development only", () => {
    expect(computeCredentialQuickstart({
      delegateUrl: "http://127.0.0.1:3000",
      projectId: "local_project",
    })).toContain("http://127.0.0.1:3000");
    expect(() => computeCredentialQuickstart({
      delegateUrl: "http://delegate.example",
      projectId: "local_project",
    })).toThrow(/must be HTTPS/);
  });

  it("rejects shell metacharacters, URL credentials, and malformed project ids", () => {
    for (const delegateUrl of [
      "https://delegate.example/'oops",
      "https://user:pass@delegate.example",
      "https://delegate.example/?token=secret",
    ]) {
      expect(() => computeCredentialQuickstart({
        delegateUrl,
        projectId: "project_123",
      })).toThrow();
    }
    expect(() => computeCredentialQuickstart({
      delegateUrl: "https://delegate.example",
      projectId: "../../escape",
    })).toThrow(/project id/);
  });
});
