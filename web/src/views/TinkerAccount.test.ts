import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import { TinkerAccount } from "./TinkerAccount";
import tinkerAccountSource from "./TinkerAccount.tsx?raw";

function renderAccount(): string {
  return renderToString(() => createComponent(TinkerAccount, {
    requestWalletConnection: () => undefined,
    openCompute: () => undefined,
  }));
}

describe("Tinker delegated account console", () => {
  it("renders the complete lifecycle while keeping an unconfigured release closed", () => {
    const html = renderAccount();

    expect(html).toContain("Delegated Tinker account");
    expect(html).toContain("Select owner wallet");
    expect(html).toContain("signed nonce challenge establishes service authorization");
    expect(html).toContain("Establish account");
    expect(html).toContain("Freeze policy");
    expect(html).toContain("Use capacity");
    expect(html).toContain("Request CVM account creation");
    expect(html).toContain("Request sealed account link");
    expect(html).toContain("Custody + encumbrance");
    expect(html).toContain("Allowance and execution policy");
    expect(html).toContain("See exactly what the contract can authorize");
    expect(html).toContain("EXACT OPERATION LOOKUP");
    expect(html).toContain("Issue or end delegation");
    expect(html).toContain("Inference and training spend");
    expect(html).toContain("Release-gated control plane");
    expect(html).toContain("configuration alone is not evidence");
  });

  it("describes opaque binding without identifier, provisioning, or identity-proof overclaims", () => {
    const html = renderAccount();

    expect(html).toContain("high-entropy, two-reviewer opaque account-binding handle");
    expect(html).toContain("not an email or provider-ID hash");
    expect(html).toContain("later measured service binds that handle to an authenticated provider account");
    expect(html).toContain("linkable if reused");
    expect(html).toContain("not cryptographic proof of the provider's internal identity");
    expect(tinkerAccountSource).toContain(
      "Activation still requires an independent attested provisioning result",
    );
    expect(tinkerAccountSource).toContain(
      "Request recorded; provider account existence is still false",
    );
  });

  it("labels a current authenticated API record as observed and live-capable without claiming fresh TDX or QVL", () => {
    expect(tinkerAccountSource).toContain(
      "Authenticated API record · live-capable",
    );
    expect(tinkerAccountSource).toContain(
      "The current customer API returned this wallet-owned bounded record",
    );
    expect(tinkerAccountSource).toContain(
      "retained evidence—not a fresh browser, Intel TDX, or QVL verification",
    );
    expect(tinkerAccountSource).toContain(
      "Every mutation must still pass a fresh server-side release gate",
    );
    expect(tinkerAccountSource).toContain(
      'class={`environment-banner ${currentApiRecordObserved() ? "live" : "warning"} tinker-release-banner`}',
    );
    expect(tinkerAccountSource).toContain(
      'state={activeAccount() ? "live" : "modeled"}',
    );
    expect(tinkerAccountSource).toContain(
      "Observed API policy · live-capable",
    );
    expect(tinkerAccountSource).toContain(
      "Observed API activation · live-capable",
    );
    expect(tinkerAccountSource).toContain(
      "Observed API · ${credential.status}",
    );
    expect(tinkerAccountSource).toContain("Observed API activation record");
    expect(tinkerAccountSource).toContain(
      "Fresh gate rechecked on every mutation",
    );
    expect(tinkerAccountSource).not.toContain("Live bounded lifecycle response");
    expect(tinkerAccountSource).not.toContain("Live policy read");
    expect(tinkerAccountSource).not.toContain("Runtime gate passed for this response");
    expect(tinkerAccountSource).not.toContain("Live gate reported not halted");
  });

  it("separates exact assets, noncash test credits, and future hosted card funding", () => {
    const html = renderAccount();

    expect(html).toContain("Compute inference/training vault");
    expect(html).toContain("same-asset withdrawal claim");
    expect(html).toContain("No token minting");
    expect(html).toContain("does not fund direct customer Tinker validation");
    expect(html).toContain("top up an upstream provider account");
    expect(html).toContain("operator-prefunded sealed capacity");
    expect(html).toContain("not this vault");
    expect(html).toContain("Operator test credits");
    expect(html).toContain("non-transferable, non-redeemable");
    expect(html).toContain("Provider-hosted checkout");
    expect(html).toContain("does not collect, proxy, log, or store card details");
  });

  it("keeps every lifecycle mutation disabled until release, wallet, chain, and session gates pass", () => {
    const html = renderAccount();
    const mutationButtons = [
      ...html.matchAll(
        /<button[^>]*data-tinker-mutation="[^"]+"[^>]*>[\s\S]*?<\/button>/g,
      ),
    ];

    expect(mutationButtons.length).toBeGreaterThanOrEqual(3);
    for (const [button] of mutationButtons) {
      expect(button).toContain("disabled");
    }

    expect(tinkerAccountSource).toContain(
      'data-tinker-status={`funding-${rail.key}`}',
    );
    expect(tinkerAccountSource).toContain(
      'data-tinker-status="save-allowance"',
    );
    expect(tinkerAccountSource).toContain(
      'data-tinker-status={`start-${row.key}`}',
    );
    expect(tinkerAccountSource).toContain(
      'class="secondary-button tinker-nonaction-status" role="status"',
    );
    expect(tinkerAccountSource).not.toContain(
      'data-tinker-mutation={`funding-${rail.key}`}',
    );
    expect(tinkerAccountSource).not.toContain(
      'data-tinker-mutation={`start-${row.key}`}',
    );
    expect(tinkerAccountSource).toContain(
      'disabled={!lifecycleReady() || !activeAccount() || Boolean(busy())}',
    );
    expect(tinkerAccountSource).toContain(
      'disabled={!lifecycleReady() || Boolean(busy())}',
    );
    expect(tinkerAccountSource).toContain(
      'data-tinker-action="authorize-lifecycle"',
    );
    expect(tinkerAccountSource).toContain(
      "Authorize a current Base Sepolia Tinker session before revoking authority",
    );
    expect(tinkerAccountSource).toContain("deployment.tinkerCustomerEnabled");
    expect(tinkerAccountSource).not.toContain("deployment.computeConsoleEnabled");
  });

  it("invalidates all in-memory authority on wallet, chain, auth-version, or expiry drift", () => {
    expect(tinkerAccountSource).toMatch(
      /wallet\.authorizationVersion\(\)[\s\S]*wallet\.account\(\)\?\.toLowerCase\(\)[\s\S]*wallet\.chainId\(\)/,
    );
    expect(tinkerAccountSource).toContain("clearLifecycleSession()");
    expect(tinkerAccountSource).toContain("currentSession.expiresAt * 1_000");
    expect(tinkerAccountSource).toContain(
      "The wallet-scoped Tinker session expired. Authorize again to continue.",
    );
    expect(tinkerAccountSource).toContain(
      "generation === lifecycleGeneration",
    );
    expect(tinkerAccountSource).toContain(
      "lifecycleContextIsCurrent",
    );
  });

  it("exposes approved account and credential lifecycle calls with fail-safe rotation", () => {
    for (const symbol of [
      "fetchCurrentTinkerAccount",
      "fetchTinkerAccount",
      "requestTinkerAccount",
      "listTinkerCredentials",
      "issueTinkerCredential",
      "rotateTinkerCredential",
      "revokeTinkerCredential",
      "revokeTinkerAccount",
    ]) {
      expect(tinkerAccountSource).toContain(symbol);
    }

    expect(tinkerAccountSource).toContain(
      "prior credential is terminally revoked before the replacement is issued",
    );
    expect(tinkerAccountSource).toContain(
      "revoke old → issue new · no overlap",
    );
    expect(tinkerAccountSource).toContain(
      "Loaded the newest {credentials().length} of {totalCredentials()} credential records",
    );
    expect(tinkerAccountSource).toContain(
      "The opaque cursor is bound to this account and authenticated store snapshot",
    );
    expect(tinkerAccountSource).toContain(
      'data-tinker-pagination="load-more"',
    );
    expect(tinkerAccountSource).toContain(
      'data-tinker-pagination="restart"',
    );
    expect(tinkerAccountSource).toContain(
      "setCredentialHistory(appendTinkerCredentialPage(history, page))",
    );
    expect(tinkerAccountSource).toContain(
      "cause instanceof TinkerRequestError && cause.restartRequired",
    );
    expect(tinkerAccountSource).toContain(
      "historyEpoch !== credentialHistoryEpoch",
    );
    expect(tinkerAccountSource).toContain(
      "credentialHistory()?.next_cursor !== cursor",
    );
  });

  it("hands implemented funding and dispatch work to exact Compute tabs", () => {
    const html = renderAccount();

    expect(html).toContain('data-tinker-handoff="compute-funding"');
    expect(html).toContain("Open Compute funding");
    expect(html).toContain('data-tinker-handoff="compute-credentials"');
    expect(html).toContain("purpose-separated from Tinker delegation");
    expect(html).toContain('data-tinker-handoff="compute-dispatch"');
    expect(html).toContain("Open Compute dispatch");

    expect(tinkerAccountSource).toContain('props.openCompute?.("funding")');
    expect(tinkerAccountSource).toContain('props.openCompute?.("credentials")');
    expect(tinkerAccountSource).toContain('props.openCompute?.("dispatch")');
    expect(tinkerAccountSource).toContain(
      'data-tinker-status="save-allowance"',
    );
    expect(tinkerAccountSource).not.toContain(
      'data-tinker-mutation="save-allowance"',
    );
    expect(tinkerAccountSource).toContain(
      "Lower-only allowance update · API schema pending",
    );
  });

  it("accepts only bounded credential and training controls, never provider secrets, training data, or card data", () => {
    const inputs = [...tinkerAccountSource.matchAll(/<input\b/g)];

    expect(inputs).toHaveLength(5);
    expect(tinkerAccountSource).toContain('type="number"');
    expect(tinkerAccountSource).toContain('inputmode="numeric"');
    expect(tinkerAccountSource).not.toMatch(/<textarea\b|<select\b/);
    expect(tinkerAccountSource).not.toContain("fetch(");
    expect(tinkerAccountSource).not.toContain("tml-");
    expect(tinkerAccountSource).not.toContain("private-key");
    expect(tinkerAccountSource).not.toMatch(
      /\blocalStorage\b|\bsessionStorage\b|\bindexedDB\b/,
    );
    expect(tinkerAccountSource).toContain("Never paste an upstream API key");
    expect(tinkerAccountSource).toContain("No keys, cards, provider balance, or user funds");
    expect(tinkerAccountSource).toContain(
      "Plaintext and any recovery context are held only in component memory",
    );
    expect(tinkerAccountSource).toContain("Authority ceiling");
    expect(tinkerAccountSource).toContain("Training steps");
    expect(tinkerAccountSource).toContain("Execution TTL");
    expect(tinkerAccountSource).toContain(
      "no prompt, dataset, Compute-vault asset, provider key, or billing credential crosses this form",
    );
  });

  it("submits a bounded customer training run and exposes fail-safe reconciliation truth", () => {
    expect(tinkerAccountSource).toContain("executeTinkerCustomerTraining");
    expect(tinkerAccountSource).toContain('data-tinker-mutation="submit-training"');
    expect(tinkerAccountSource).toContain("Claim authority + submit training");
    expect(tinkerAccountSource).toContain(
      "at most once per durable claim",
    );
    expect(tinkerAccountSource).toContain(
      "Automatic provider redispatch is disabled.",
    );
    expect(tinkerAccountSource).toContain(
      "Observed API settlement · live-capable",
    );
    expect(tinkerAccountSource).toContain(
      "Observed API hold · reconcile",
    );
    expect(tinkerAccountSource).toContain(
      "provider-authoritative billing: no",
    );
    expect(tinkerAccountSource).toContain(
      "Compute-vault assets are not charged",
    );
  });

  it("recovers only the retained signed result and blocks drift or new work while held", () => {
    expect(tinkerAccountSource).toContain("recoverTinkerCustomerTraining");
    expect(tinkerAccountSource).toContain(
      "trainingRecoveryContextIsCurrent",
    );
    expect(tinkerAccountSource).toContain(
      'data-tinker-action="recover-training"',
    );
    expect(tinkerAccountSource).toContain("Recover signed result");
    expect(tinkerAccountSource).toContain(
      "context.idempotencyKey",
    );
    expect(tinkerAccountSource).toContain(
      "context.controls",
    );
    expect(tinkerAccountSource).toContain(
      "context.credentialToken",
    );
    expect(tinkerAccountSource).toContain(
      "No signed result is available yet. The original reconciliation hold remains open",
    );
    expect(tinkerAccountSource).toContain(
      "it cannot create a new reservation or redispatch provider work",
    );
    expect(tinkerAccountSource).toContain(
      "New training blocked by hold",
    );
    expect(tinkerAccountSource).toContain(
      'disabled={!trainingRecoveryContextIsCurrent() || Boolean(busy())}',
    );
  });
});
