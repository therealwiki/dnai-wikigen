import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ComputeHttpError } from "../lib/compute";
import { authorizeComputeSessionForCurrentWallet, computeRequestMayReport, createComputeCredentialDialog, createComputeSessionLifetime, handleComputeChildSessionRejection } from "./Compute";
import computeSource from "./Compute.tsx?raw";

const NOW = 1_800_000_000;

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW * 1_000);
});
afterEach(() => vi.useRealTimers());

describe("Compute wallet authorization context", () => {
  const address = "0x1111111111111111111111111111111111111111" as const;
  const response = {
    access_token: "authorized-session", token_type: "Bearer" as const, address,
    issued_at: NOW, expires_at: NOW + 600, scopes: ["compute:console"],
  };

  it("supports an initial switch to Base Sepolia before binding the signing version", async () => {
    let correctChain = false;
    let version = 1;
    const source = {
      account: () => address,
      isCorrectChain: () => correctChain,
      authorizationVersion: () => version,
      switchToBase: vi.fn(async () => { correctChain = true; version += 1; }),
      authorizeComputeConsole: vi.fn(async () => {
        expect(correctChain).toBe(true);
        expect(version).toBe(2);
        return response;
      }),
    };
    await expect(authorizeComputeSessionForCurrentWallet(source, () => true)).resolves.toEqual({ token: response, walletVersion: 2 });
    expect(source.switchToBase).toHaveBeenCalledTimes(1);
    expect(source.authorizeComputeConsole).toHaveBeenCalledTimes(1);
  });

  it("rejects later wallet-version drift even if the final account and chain look unchanged", async () => {
    let version = 1;
    const source = {
      account: () => address,
      isCorrectChain: () => true,
      authorizationVersion: () => version,
      switchToBase: vi.fn(async () => undefined),
      authorizeComputeConsole: vi.fn(async () => { version += 2; return response; }),
    };
    await expect(authorizeComputeSessionForCurrentWallet(source, () => true)).rejects.toThrow("Wallet session changed");
    expect(source.switchToBase).not.toHaveBeenCalled();
  });

  it("does not start signing if the authorization attempt was invalidated during chain switch", async () => {
    let current = true;
    let correctChain = false;
    const source = {
      account: () => address,
      isCorrectChain: () => correctChain,
      authorizationVersion: () => 1,
      switchToBase: vi.fn(async () => { correctChain = true; current = false; }),
      authorizeComputeConsole: vi.fn(async () => response),
    };
    await expect(authorizeComputeSessionForCurrentWallet(source, () => current)).rejects.toThrow("Wallet session changed");
    expect(source.authorizeComputeConsole).not.toHaveBeenCalled();
  });
});

describe("Compute session deadline", () => {
  it("expires at the backend's ten-minute deadline and permits a fresh authorization", () => {
    const expired = vi.fn();
    const lifetime = createComputeSessionLifetime(expired);
    lifetime.install("first-session", NOW + 600);
    vi.advanceTimersByTime(599_999);
    expect(lifetime.current("first-session")).toBe(true);
    expect(expired).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(lifetime.current("first-session")).toBe(false);
    expect(expired).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
    lifetime.install("reauthorized-session", NOW + 1_200);
    expect(lifetime.current("reauthorized-session")).toBe(true);
    lifetime.clear();
  });

  it("rejects an expired session synchronously when a suspended tab has not run its timer", () => {
    const expired = vi.fn();
    const lifetime = createComputeSessionLifetime(expired);
    lifetime.install("session", NOW + 600);
    vi.setSystemTime((NOW + 601) * 1_000);
    expect(expired).not.toHaveBeenCalled();
    expect(lifetime.current("session")).toBe(false);
    expect(expired).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
    expect(lifetime.current("session")).toBe(false);
    expect(expired).toHaveBeenCalledTimes(1);
  });

  it("replacing a session cancels its old timer and rejects old async context", () => {
    const expired = vi.fn();
    const lifetime = createComputeSessionLifetime(expired);
    lifetime.install("old-session", NOW + 10);
    lifetime.install("new-session", NOW + 600);
    expect(vi.getTimerCount()).toBe(1);
    vi.advanceTimersByTime(10_000);
    expect(lifetime.current("old-session")).toBe(false);
    expect(lifetime.current("new-session")).toBe(true);
    expect(expired).not.toHaveBeenCalled();
    lifetime.clear();
  });

  it("clearing on lock or unmount cancels callbacks and invalidates requests", () => {
    const expired = vi.fn();
    const lifetime = createComputeSessionLifetime(expired);
    lifetime.install("session", NOW + 600);
    lifetime.clear();
    expect(lifetime.current("session")).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
    vi.advanceTimersByTime(900_000);
    expect(expired).not.toHaveBeenCalled();
  });

  it.each([NOW, NOW - 1, NOW + 0.5, Number.NaN, Number.POSITIVE_INFINITY])(
    "does not authorize an invalid or already expired deadline: %s",
    (deadline) => {
      const lifetime = createComputeSessionLifetime(vi.fn());
      expect(() => lifetime.install("session", deadline)).toThrow(/expired|invalid expiry/);
      expect(lifetime.current("session")).toBe(false);
      expect(vi.getTimerCount()).toBe(0);
    },
  );
});

describe("Compute HTTP session rejection", () => {
  it("accepts a child HTTP 401 only for the original, current wallet session", () => {
    const rejected = vi.fn();
    let walletVersion = 1;
    const lifetime = createComputeSessionLifetime(vi.fn());
    lifetime.install("old-wallet-session", NOW + 600);
    const current = (token: string) => walletVersion === 1 && lifetime.current(token);
    handleComputeChildSessionRejection("old-wallet-session", current, rejected);
    expect(rejected).toHaveBeenCalledTimes(1);
    rejected.mockClear();
    lifetime.install("new-wallet-session", NOW + 600);
    handleComputeChildSessionRejection("old-wallet-session", current, rejected);
    handleComputeChildSessionRejection("separate-device-credential", current, rejected);
    walletVersion = 2;
    handleComputeChildSessionRejection("new-wallet-session", current, rejected);
    handleComputeChildSessionRejection("", current, rejected);
    expect(rejected).not.toHaveBeenCalled();
    lifetime.clear();
  });

  it("locks only the current authenticated session on an explicit 401", () => {
    const rejected = vi.fn();
    expect(computeRequestMayReport(new ComputeHttpError(401, "Session rejected"), () => true, rejected)).toBe(false);
    expect(rejected).toHaveBeenCalledTimes(1);
  });

  it.each([new ComputeHttpError(403, "Role denied"), new ComputeHttpError(503, "Unavailable"), new Error("Network error mentioning 401")])(
    "preserves authorization for non-401 or untyped failures: %s",
    (cause) => {
      const rejected = vi.fn();
      expect(computeRequestMayReport(cause, () => true, rejected)).toBe(true);
      expect(rejected).not.toHaveBeenCalled();
    },
  );

  it("a stale request's 401 cannot lock a freshly reauthorized session", () => {
    const rejected = vi.fn();
    const lifetime = createComputeSessionLifetime(vi.fn());
    lifetime.install("old-session", NOW + 600);
    lifetime.install("new-session", NOW + 600);
    expect(computeRequestMayReport(new ComputeHttpError(401, "Session rejected"), () => lifetime.current("old-session"), rejected)).toBe(false);
    expect(lifetime.current("new-session")).toBe(true);
    expect(rejected).not.toHaveBeenCalled();
    lifetime.clear();
  });
});

function dialogFixture() {
  const publish = vi.fn();
  const dialog = createComputeCredentialDialog(publish);
  const latest = () => publish.mock.lastCall?.[0] as { open: boolean; pending: boolean; token: string };
  dialog.open();
  return { dialog, publish, latest };
}

describe("Compute one-time credential delivery", () => {
  it("keeps every close attempt and new-dialog attempt from losing a pending token", async () => {
    const { dialog, latest } = dialogFixture();
    const attempt = dialog.begin(() => true)!;
    let complete!: (token: string) => void;
    const completion = new Promise<string>((resolve) => { complete = resolve; })
      .then((token) => dialog.deliver(attempt, token));

    // Backdrop, Escape, X, and acknowledgement all use the same close guard.
    for (let route = 0; route < 4; route += 1) expect(dialog.close()).toBe(false);
    expect(dialog.open()).toBe(false);
    expect(dialog.begin(() => true)).toBeUndefined();
    expect(latest()).toEqual({ open: true, pending: true, token: "" });
    complete("one-time-secret");
    expect(await completion).toBe(true);
    expect(latest()).toEqual({ open: true, pending: false, token: "one-time-secret" });
    expect(dialog.open()).toBe(false);
    expect(dialog.close()).toBe(true);
    expect(latest()).toEqual({ open: false, pending: false, token: "" });
  });

  it("releases the close guard after an issuance failure without retaining a secret", () => {
    const { dialog, latest } = dialogFixture();
    const attempt = dialog.begin(() => true)!;
    dialog.finish(attempt);
    expect(latest()).toEqual({ open: true, pending: false, token: "" });
    expect(dialog.close()).toBe(true);
    expect(dialog.deliver(attempt, "late-secret")).toBe(false);
    expect(latest().token).toBe("");
  });

  it.each(["wallet", "project", "unmount"])(
    "discards deferred decryption after %s invalidation, even after returning to the original scope",
    async () => {
      const { dialog, publish, latest } = dialogFixture();
      const attempt = dialog.begin(() => true)!;
      let decrypt!: (token: string) => void;
      const completion = new Promise<string>((resolve) => { decrypt = resolve; })
        .then((token) => dialog.deliver(attempt, token));
      dialog.invalidate();
      dialog.open();
      const replacement = dialog.begin(() => true)!;
      decrypt("stale-secret");
      expect(await completion).toBe(false);
      dialog.finish(attempt);
      expect(latest()).toEqual({ open: true, pending: true, token: "" });
      expect(publish.mock.calls.every(([state]) => state.token !== "stale-secret")).toBe(true);
      expect(dialog.deliver(replacement, "current-secret")).toBe(true);
      dialog.invalidate();
      expect(latest()).toEqual({ open: false, pending: false, token: "" });
    },
  );

  it("checks current wallet/project generation again at plaintext delivery", () => {
    const { dialog, publish } = dialogFixture();
    let scopeVersion = 1;
    const expected = scopeVersion;
    const attempt = dialog.begin(() => scopeVersion === expected)!;
    scopeVersion += 2; // A -> B -> A must not restore the old async authority.
    expect(dialog.current(attempt)).toBe(false);
    expect(dialog.deliver(attempt, "stale-secret")).toBe(false);
    expect(publish.mock.calls.every(([state]) => state.token === "")).toBe(true);
  });

  it("expiry invalidates pending delivery before a late decrypt can expose plaintext", async () => {
    const { dialog, latest, publish } = dialogFixture();
    const recovery = vi.fn(() => dialog.invalidate());
    const lifetime = createComputeSessionLifetime(recovery);
    lifetime.install("session", NOW + 600);
    const attempt = dialog.begin(() => lifetime.current("session"))!;
    let decrypt!: (token: string) => void;
    const completion = new Promise<string>((resolve) => { decrypt = resolve; })
      .then((token) => dialog.deliver(attempt, token));
    vi.advanceTimersByTime(600_000);
    decrypt("expired-secret");
    expect(await completion).toBe(false);
    dialog.finish(attempt);
    expect(recovery).toHaveBeenCalledTimes(1);
    expect(latest()).toEqual({ open: false, pending: false, token: "" });
    expect(publish.mock.calls.every(([state]) => state.token === "")).toBe(true);
  });
});

describe("Compute view lifecycle wiring", () => {
  it("checks current wallet authority again when either child reports rejection", () => {
    expect(computeSource.match(/onSessionRejected=\{rejectChildSession\}/g)).toHaveLength(2);
    expect(computeSource).toContain('handleComputeChildSessionRejection(requestToken, computeSessionIsCurrent, () => recoverConsoleSession("rejected"))');
    expect(computeSource).toContain("An in-flight workload upload/deletion");
  });

  it("uses the validated response expiry and cleans up lifetime and delivery on unmount", () => {
    expect(computeSource).toContain("sessionLifetime.install(token.access_token, token.expires_at)");
    expect(computeSource).toContain("sessionLifetime.current(token)");
    expect(computeSource).toMatch(/onCleanup\(\(\) => \{\s*disposed = true;\s*lockConsole\(\);/);
    const lock = computeSource.slice(computeSource.indexOf("function lockConsole()"), computeSource.indexOf("function computeSessionIsCurrent("));
    expect(lock).toContain("sessionLifetime.clear()");
    expect(lock).toContain("credentialDialog.invalidate()");
    expect(lock).toContain("deviceKeys.clear()");
  });

  it("routes Escape, backdrop, X, and acknowledgement through the pending-close guard", () => {
    expect(computeSource).toContain("useModalFocus(keyOpen, () => credentialDialogRef, closeKeyDialog)");
    expect(computeSource).toMatch(/function closeKeyDialog\(\): void \{\s*credentialDialog.close\(\);/);
    expect(computeSource.match(/onClick=\{closeKeyDialog\}/g)).toHaveLength(3);
    expect(computeSource).toContain('aria-label="Close credential dialog" data-autofocus onClick={closeKeyDialog} disabled={credentialPending()}');
    expect(computeSource).toContain("scope === projectScopeVersion");
    expect(computeSource.match(/credentialDialog.deliver\(attempt, plaintext\)/g)).toHaveLength(2);
  });

  it("exposes reauthorization and original-project recovery without automatically repeating mutations", () => {
    expect(computeSource).toContain("Reauthorize Compute Console");
    expect(computeSource).toContain("item.project_id === expiryRecovery()?.projectId");
    expect(computeSource).toContain("revoke any unreceived credential before issuing another");
    expect(computeSource).toContain("nothing will be resealed, authorized, or submitted automatically");
    expect(computeSource).toContain("may already have committed even without a returned receipt");
    expect(computeSource).not.toMatch(/(?:localStorage|sessionStorage)\.(?:setItem|getItem)/);
  });

  it("preserves reconciliation context through a canceled or failed reauthorization", () => {
    const lock = computeSource.slice(computeSource.indexOf("function lockConsole()"), computeSource.indexOf("function computeSessionIsCurrent("));
    expect(lock).not.toContain("setExpiryRecovery");
    const unlock = computeSource.slice(computeSource.indexOf("async function unlockConsole()"), computeSource.indexOf("function openExactDispatch("));
    expect(unlock).not.toContain("setExpiryRecovery");
    expect(unlock).toContain("item.project_id === expiryRecovery()?.projectId");
    expect(computeSource).toContain("setExpiryRecovery(!originalProject && previous ? previous : recovery)");
    expect(computeSource).toContain("recovery.walletVersion !== wallet.authorizationVersion()");
  });

  it("does not post stale clipboard status after a session/project change or dismissal", () => {
    const copy = computeSource.slice(computeSource.indexOf("async function copyOneTimeToken()"), computeSource.indexOf("function inspectJobEvidence("));
    expect(copy.match(/scope === projectScopeVersion && keyOpen\(\)/g)).toHaveLength(2);
    expect(copy.match(/await navigator.clipboard.writeText\([^\n]+\);\s*if \(!contextIsCurrent\(\)\) return;/g)).toHaveLength(2);
    expect(copy).toContain("oneTimeToken() === plaintext");
  });
});
